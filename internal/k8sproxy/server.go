package k8sproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"

	"github.com/hrntknr/sb/internal/util"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// Serve accepts downstream requests whose path prefix names the kubeconfig
// context ("/<context>/api/...") and whose bearer token was issued for that
// context.
func (p *Proxy) Serve(l net.Listener) error {
	certificate, err := p.certificate()
	if err != nil {
		return fmt.Errorf("k8s: issue certificate: %w", err)
	}
	slog.Info("serving k8s proxy", "addr", l.Addr().String())
	server := &http.Server{
		Handler: http.HandlerFunc(p.serveHTTP),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		},
	}
	p.setServer(server)
	return server.ServeTLS(l, "", "")
}

// Shutdown stops the server: it stops accepting new requests, waits for
// active ones to finish, and closes the rest at ctx's deadline (streams
// that never go idle, like watch and logs -f, are cut there). Call
// BeginStop first to cancel the upstream requests at the start of the
// shutdown.
func (p *Proxy) Shutdown(ctx context.Context) {
	server := p.getServer()
	if server == nil {
		return
	}
	if err := server.Shutdown(ctx); err != nil {
		server.Close()
	}
}

// BeginStop starts the shutdown: each upstream request still running is
// cancelled here, so the streams the shutdown would wait for are cut
// before it. Shutdown then waits for the connections' cleanups.
func (p *Proxy) BeginStop() {
	p.stopState()
	p.stopMu.Lock()
	cancel := p.stopCancel
	p.stopMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// stopState returns the proxy's shared stop state: a context cancelled
// when the shutdown begins. It is created on first use, so requests
// issued after the shutdown began inherit its cancellation.
func (p *Proxy) stopState() context.Context {
	p.stopMu.Lock()
	defer p.stopMu.Unlock()
	if p.stopCtx == nil {
		p.stopCtx, p.stopCancel = context.WithCancel(context.Background())
	}
	return p.stopCtx
}

// stopContext returns a context that is cancelled when the shutdown begins
// (BeginStop), or when base is — whichever comes first.
func (p *Proxy) stopContext(base context.Context) context.Context {
	return util.StoppedContext(p.stopState(), base)
}

func (p *Proxy) setServer(server *http.Server) {
	p.mu.Lock()
	p.server = server
	p.mu.Unlock()
}

func (p *Proxy) getServer() *http.Server {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.server
}

// certificate issues the proxy's self-signed TLS certificate once. The same
// certificate is served and embedded in the generated kubeconfig as the
// cluster trust anchor, and it covers the configured host.
func (p *Proxy) certificate() (tls.Certificate, error) {
	p.certOne.Do(func() {
		p.cert, p.certErr = util.IssueCertificate(p.host)
	})
	return p.cert, p.certErr
}

// SetTargets replaces the policy targets, called on config reloads.
func (p *Proxy) SetTargets(targets Targets) {
	p.mu.Lock()
	p.Targets = targets
	p.mu.Unlock()
}

// allows reports whether the current policy permits the request.
func (p *Proxy) allows(context string, info *apirequest.RequestInfo) bool {
	p.mu.RLock()
	targets := p.Targets
	p.mu.RUnlock()
	return targets.Allows(context, info)
}

// resolveConnections loads the source kubeconfig and resolves the policy's
// upstream connections from it, fixing them for the session. A context the
// policy names that is missing from the source — or whose cluster or user
// entry does not resolve — is an error.
func (p *Proxy) resolveConnections() error {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	raw, err := loadingRules.Load()
	if err != nil {
		return fmt.Errorf("load upstream kubeconfig: %w", err)
	}
	return p.resolveConnectionsFrom(raw, loadingRules)
}

// resolveConnectionsFrom resolves the policy's upstream connections from
// an already-loaded source kubeconfig and stores them, fixing the session's
// connections. A context that does not resolve — one missing from the
// source kubeconfig — is an error.
func (p *Proxy) resolveConnectionsFrom(raw *api.Config, loadingRules *clientcmd.ClientConfigLoadingRules) error {
	p.mu.RLock()
	targets := p.Targets
	p.mu.RUnlock()
	connections, err := resolveUpstreams(raw, loadingRules, policyContexts(targets))
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.connections = connections
	p.mu.Unlock()
	return nil
}

// connection returns the connection resolved for context, nil when the
// policy does not name it.
func (p *Proxy) connection(context string) *upstream {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connections[context]
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.RLock()
	context := p.tokens[token]
	p.mu.RUnlock()
	if token == "" || context == "" {
		slog.Warn("rejected k8s request with invalid token", "method", r.Method, "path", r.URL.EscapedPath(), "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if rejectedRequest(r) {
		slog.Warn("rejected k8s request with unexpected headers", "context", context, "method", r.Method, "path", r.URL.EscapedPath())
		http.Error(w, "unsupported request", http.StatusBadRequest)
		return
	}
	decodedPath, rawPath, wrongContext, ok := upstreamRequestPath(r.URL, context)
	switch {
	case wrongContext:
		// The token is used on another context's URL: a token works
		// only on its own context's URL.
		slog.Warn("rejected k8s request on another context's URL", "context", context, "method", r.Method, "path", r.URL.EscapedPath())
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	case !ok:
		slog.Warn("rejected k8s request with bad path", "context", context, "method", r.Method, "path", r.URL.EscapedPath())
		http.Error(w, "bad request path", http.StatusBadRequest)
		return
	}
	info, err := classifyRequest(r.Method, decodedPath, r.URL.RawQuery)
	if err != nil {
		slog.Warn("rejected k8s request with bad path", "context", context, "method", r.Method, "path", decodedPath)
		http.Error(w, "bad request path", http.StatusBadRequest)
		return
	}
	if !validAPIPath(decodedPath, rawPath) {
		slog.Warn("rejected k8s request with malformed path", "context", context, "method", r.Method, "path", decodedPath)
		http.Error(w, "bad request path", http.StatusBadRequest)
		return
	}
	if !p.allows(context, info) {
		slog.Warn("rejected k8s request by policy", "context", context, "method", r.Method, "path", decodedPath)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	conn := p.connection(context)
	if conn == nil {
		slog.Error("no resolved upstream connection", "context", context, "method", r.Method, "path", decodedPath)
		http.Error(w, "bad upstream config", http.StatusBadGateway)
		return
	}
	joinedDecoded, joinedRaw, err := joinBasePath(conn.target, rawPath)
	if err != nil {
		// Not reachable through a request the proxy server parsed: the
		// target's and the request's escaped paths are both valid
		// escapes. The path cannot go upstream joined, so it stops here.
		slog.Warn("rejected k8s request with bad path", "context", context, "method", r.Method, "path", rawPath)
		http.Error(w, "bad request path", http.StatusBadRequest)
		return
	}
	slog.Debug("proxying k8s request", "context", context, "method", r.Method, "path", decodedPath, "target", conn.target.Host)
	proxy := &httputil.ReverseProxy{
		Transport: conn.transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Error("k8s upstream request failed", "context", context, "method", r.Method, "path", decodedPath, "error", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.URL.Scheme = conn.target.Scheme
			req.Out.URL.Host = conn.target.Host
			// The fixed server is kept, base path and its escapes
			// included: a server under https://gateway.example/k8s
			// receives /k8s/api/v1/..., one behind an escaped
			// separator (https://gateway.example/k8s%2F) receives
			// /k8s%2F/api/v1/....
			req.Out.URL.Path = joinedDecoded
			req.Out.URL.RawPath = joinedRaw
			req.Out.Host = conn.target.Host
			// The downstream Authorization does not pass upstream: the
			// connection's transport sets the upstream one per request,
			// so a token file auth setting refreshes from the file as
			// it would without sb.
			req.Out.Header.Del("Authorization")
		},
	}
	// The upstream request carries the stop context: cancelled when the
	// shutdown begins, it cuts the streams (watch, logs -f) the graceful
	// shutdown would otherwise wait for.
	proxy.ServeHTTP(w, r.WithContext(p.stopContext(r.Context())))
}

// transportConfigForContext tags the rest config host so per-context OIDC
// auth providers get separate transports (and token caches).
func transportConfigForContext(config *rest.Config, context string) *rest.Config {
	transportConfig := rest.CopyConfig(config)
	if transportConfig.AuthProvider != nil && transportConfig.AuthProvider.Name == "oidc" {
		transportConfig.Host = oidcCacheHost(transportConfig.Host, context, transportConfig.AuthProvider.Config)
	}
	return transportConfig
}

func oidcCacheHost(host, context string, authProviderConfig map[string]string) string {
	hash := sha256.New()
	keys := make([]string, 0, len(authProviderConfig))
	for key := range authProviderConfig {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(authProviderConfig[key]))
		_, _ = hash.Write([]byte{0})
	}
	return host + "#" + url.PathEscape(context) + ":" + hex.EncodeToString(hash.Sum(nil))
}
