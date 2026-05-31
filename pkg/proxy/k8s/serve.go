package k8s

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

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

func (p *Proxy) Serve(l net.Listener) error {
	if p == nil {
		return fmt.Errorf("k8s: nil Proxy")
	}
	if l == nil {
		return fmt.Errorf("k8s: nil listener")
	}
	certificate, err := issueCertificate()
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
	return server.ServeTLS(l, "", "")
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
	if len(p.Targets) > 0 && !p.Targets.Allows(requestVerb(r.Method, upstreamPath), context) {
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
	transport, err := rest.TransportFor(config)
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
	proxy.ServeHTTP(w, r)
}

func requestVerb(method, path string) Verb {
	info, err := requestInfoFactory.NewRequestInfo(&http.Request{
		Method: method,
		URL:    &url.URL{Path: path},
	})
	if err == nil && info.IsResourceRequest {
		if info.APIGroup == "authorization.k8s.io" &&
			info.Resource == "selfsubjectaccessreviews" &&
			info.Verb == "create" {
			return Read
		}
		switch info.Subresource {
		case "attach", "exec", "portforward", "proxy":
			return ReadWrite
		}
		switch info.Verb {
		case "get", "list", "watch":
			return Read
		default:
			return ReadWrite
		}
	}

	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return Read
	default:
		return ReadWrite
	}
}

func upstreamRequestPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/")
	if _, rest, ok := strings.Cut(path, "/"); ok {
		return "/" + rest, true
	}
	return "", false
}

func issueCertificate() (tls.Certificate, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "proxy"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
}
