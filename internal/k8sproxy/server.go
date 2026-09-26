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
	"k8s.io/apimachinery/pkg/util/sets"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var requestInfoFactory = &apirequest.RequestInfoFactory{
	APIPrefixes:          sets.NewString("api", "apis"),
	GrouplessAPIPrefixes: sets.NewString("api"),
}

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
	p.stopMu.Lock()
	cancels := p.stopCancels
	p.stopMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

// stopContext returns a context that is cancelled when the shutdown begins
// (BeginStop), or when base is — whichever comes first.
func (p *Proxy) stopContext(base context.Context) context.Context {
	ctx, cancel := context.WithCancel(base)
	p.stopMu.Lock()
	p.stopCancels = append(p.stopCancels, cancel)
	p.stopMu.Unlock()
	return ctx
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
func (p *Proxy) allows(verb Verb, context, namespace string) bool {
	p.mu.RLock()
	targets := p.Targets
	p.mu.RUnlock()
	return targets.Allows(verb, context, namespace)
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
	upstreamPath, ok := upstreamRequestPath(r.URL.EscapedPath())
	if !ok {
		slog.Warn("rejected k8s request with bad path", "context", context, "method", r.Method, "path", r.URL.EscapedPath())
		http.Error(w, "bad request path", http.StatusBadRequest)
		return
	}
	verb, namespace := classifyRequest(r.Method, upstreamPath)
	if !p.allows(verb, context, namespace) {
		slog.Warn("rejected k8s request by policy", "context", context, "method", r.Method, "path", upstreamPath)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	rawConfig, err := loadingRules.Load()
	if err != nil {
		slog.Error("failed to load upstream kubeconfig", "context", context, "error", err)
		http.Error(w, "bad upstream config", http.StatusBadGateway)
		return
	}
	config, err := clientcmd.NewNonInteractiveClientConfig(
		*rawConfig,
		context,
		&clientcmd.ConfigOverrides{},
		loadingRules,
	).ClientConfig()
	if err != nil {
		slog.Error("failed to resolve upstream kubeconfig context", "context", context, "error", err)
		http.Error(w, "bad upstream config", http.StatusBadGateway)
		return
	}
	transport, err := rest.TransportFor(transportConfigForContext(config, context))
	if err != nil {
		slog.Error("failed to create upstream k8s transport", "context", context, "error", err)
		http.Error(w, "bad upstream transport", http.StatusBadGateway)
		return
	}

	target, err := url.Parse(config.Host)
	if err != nil {
		slog.Error("failed to parse upstream k8s host", "context", context, "host", config.Host, "error", err)
		http.Error(w, "bad upstream host", http.StatusBadGateway)
		return
	}
	slog.Debug("proxying k8s request", "context", context, "method", r.Method, "path", upstreamPath, "target", target.Host)
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Error("k8s upstream request failed", "context", context, "method", r.Method, "path", upstreamPath, "error", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.URL.Scheme = target.Scheme
			req.Out.URL.Host = target.Host
			req.Out.URL.Path = upstreamPath
			req.Out.Host = target.Host
			req.Out.Header.Del("Authorization")
			if config.BearerToken != "" {
				req.Out.Header.Set("Authorization", "Bearer "+config.BearerToken)
			}
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

// classifyRequest maps a request to its policy verb and namespace. Read covers
// get/list/watch and self-subject access reviews; everything else (including
// exec/attach/portforward/proxy subresources) is read-write.
func classifyRequest(method, path string) (Verb, string) {
	info, err := requestInfoFactory.NewRequestInfo(&http.Request{
		Method: method,
		URL:    &url.URL{Path: path},
	})
	if err != nil || !info.IsResourceRequest {
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			return Read, ""
		}
		return ReadWrite, ""
	}

	if info.APIGroup == "authorization.k8s.io" && info.Resource == "selfsubjectaccessreviews" && info.Verb == "create" {
		return Read, info.Namespace
	}
	switch info.Subresource {
	case "attach", "exec", "portforward", "proxy":
		return ReadWrite, info.Namespace
	}
	switch info.Verb {
	case "get", "list", "watch":
		return Read, info.Namespace
	default:
		return ReadWrite, info.Namespace
	}
}

// upstreamRequestPath strips the context prefix: "/dev/api/v1/..." becomes
// "/api/v1/...".
func upstreamRequestPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/")
	if _, rest, ok := strings.Cut(path, "/"); ok {
		return "/" + rest, true
	}
	return "", false
}
