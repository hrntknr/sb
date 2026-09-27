package k8sproxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// upstream is the resolved upstream connection for one context: the
// transport with its auth settings, and the target URL. It is resolved
// once per session; requests reuse it without reloading the
// kubeconfig, and the transport keeps updating its own auth settings
// per request (a token file's refresh, an OIDC provider's expiry) as
// it would without sb.
type upstream struct {
	transport http.RoundTripper
	target    *url.URL
}

// resolveUpstreams resolves the upstream connection for every context
// named in the policy: the URL, TLS verification, and auth settings the
// source kubeconfig's context entry resolves to, fixed for the session.
// A context that does not resolve — one missing from the source
// kubeconfig, or one whose cluster or user entry does not exist — is an
// error.
func resolveUpstreams(raw *api.Config, loadingRules *clientcmd.ClientConfigLoadingRules, contexts []string) (map[string]*upstream, error) {
	if len(contexts) == 0 {
		return nil, nil
	}
	resolved := make(map[string]*upstream, len(contexts))
	for _, context := range contexts {
		if _, ok := resolved[context]; ok {
			continue
		}
		conn, err := resolveUpstream(raw, loadingRules, context)
		if err != nil {
			return nil, fmt.Errorf("resolve context %q: %w", context, err)
		}
		resolved[context] = conn
	}
	return resolved, nil
}

// resolveUpstream resolves one context's connection from the loaded
// source kubeconfig: the client config the context entry resolves to and
// the transport built from it.
func resolveUpstream(raw *api.Config, loadingRules *clientcmd.ClientConfigLoadingRules, context string) (*upstream, error) {
	config, err := clientcmd.NewNonInteractiveClientConfig(*raw, context, &clientcmd.ConfigOverrides{}, loadingRules).ClientConfig()
	if err != nil {
		return nil, err
	}
	transport, err := rest.TransportFor(transportConfigForContext(config, context))
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(config.Host)
	if err != nil {
		return nil, err
	}
	return &upstream{transport: transport, target: target}, nil
}

// joinBasePath joins the server URL's base path onto the API path: the
// upstream request goes to the fixed server, its path prefix included
// (a server under https://gateway.example/k8s gets /k8s/api/v1/...),
// and an empty base leaves the API path alone.
func joinBasePath(base, api string) string {
	if base == "" {
		return api
	}
	return strings.TrimSuffix(base, "/") + api
}

// upstreamRequestPath splits the context prefix off the downstream URL
// and returns the upstream path. The URL must name the context the token
// was issued for: a token works only on its own context's URL, so a
// request for another context's URL — one written into a kubeconfig by
// hand — is rejected. wrongContext reports that case; ok is false for
// the rest (no API path after the context prefix, or escapes that do
// not decode). decoded and raw are the upstream path in decoded and
// escaped form: the request is classified as the API server classifies
// it, and the escapes the downstream client used are forwarded as they
// were.
func upstreamRequestPath(u *url.URL, context string) (decoded, raw string, wrongContext, ok bool) {
	rawPath := u.EscapedPath()
	first, rest, found := strings.Cut(strings.TrimPrefix(rawPath, "/"), "/")
	if !found || rest == "" {
		return "", "", false, false
	}
	name, err := url.PathUnescape(first)
	if err != nil || name != context {
		return "", "", true, false
	}
	raw = "/" + rest
	decoded, err = url.PathUnescape(raw)
	if err != nil {
		return "", "", false, false
	}
	return decoded, raw, false, true
}
