package k8sproxy

import (
	"net/http"
	"net/url"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// requestInfoFactory classifies requests the same way the Kubernetes API
// server does: what the API server would authorize decides what sb
// forwards.
var requestInfoFactory = &apirequest.RequestInfoFactory{
	APIPrefixes:          sets.NewString("api", "apis"),
	GrouplessAPIPrefixes: sets.NewString("api"),
}

// classifyRequest turns a downstream request into its Kubernetes
// RequestInfo: the group, resource, subresource, verb, and namespace the
// rules are matched against are what the API server would authorize for
// the same request. path is the decoded upstream path and query its
// query.
func classifyRequest(method, path, query string) (*apirequest.RequestInfo, error) {
	return requestInfoFactory.NewRequestInfo(&http.Request{
		Method: method,
		URL:    &url.URL{Path: path, RawQuery: query},
	})
}

// validAPIPath reports whether a Kubernetes API path, in decoded and
// escaped form, is well formed: the escapes keep the raw form's
// segmentation, no segment is empty or a dot segment, the group
// prefixes are recognized with a valid version, and the resource path
// carries at most a name and a subresource after the namespaces
// prefix. The classification still decides what the path means; this
// rejects what it would read past the end of the resource the path
// names (RequestInfoFactory is not a validator).
func validAPIPath(decoded, raw string) bool {
	// An escape that decodes to a separator would change the
	// segmentation: the path forwarded upstream would not be the one
	// classified (pods/nginx%2Flog would read as pods/nginx/log there).
	if strings.Count(decoded, "/") != strings.Count(raw, "/") {
		return false
	}
	seg := strings.Split(strings.Trim(decoded, "/"), "/")
	for _, s := range seg {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	if len(seg) < 3 {
		// Too short for a resource path: a non-resource path. The
		// policy's fixed discovery set decides it.
		return true
	}
	var rest []string
	switch seg[0] {
	case "api":
		if seg[1] != "v1" {
			// The core group is v1; nothing else is a route upstream.
			return false
		}
		rest = seg[2:]
	case "apis":
		// /apis/{group}/{version}/...: any group and version — the
		// policy's rules match the group.
		rest = seg[3:]
	default:
		// Not a group prefix: a non-resource path.
		return true
	}
	// The watch special verb precedes the resource path.
	if len(rest) > 0 && rest[0] == "watch" {
		rest = rest[1:]
	}
	// The namespaces prefix selects the namespace of the resource path;
	// the namespaces resource keeps its own.
	return len(stripNamespacesPrefix(rest)) <= 3
}

// stripNamespacesPrefix strips the namespaces/{namespace} prefix off the
// resource path: the resource path is namespaced. The namespaces
// resource keeps its own — the collection, a named namespace, or a
// subresource of it (status, finalize).
func stripNamespacesPrefix(rest []string) []string {
	if len(rest) < 3 || rest[0] != "namespaces" {
		return rest
	}
	if rest[2] == "status" || rest[2] == "finalize" {
		return rest
	}
	return rest[2:]
}

// allowedDiscoveryPath reports whether a non-resource path is one of
// the fixed discovery paths a downstream client may GET: /api, /apis,
// the core /api/v1, the discovery of a group (/apis/<group>/<version>),
// openapi, and the version endpoint. Everything else a non-resource
// request asks for — /healthz, metrics, arbitrary paths — is not
// granted by any rule.
func allowedDiscoveryPath(path string) bool {
	switch path {
	case "/api", "/apis", "/version", "/openapi/v2", "/openapi/v3":
		return true
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch len(parts) {
	case 2:
		return parts[0] == "api" && parts[1] == "v1"
	case 3:
		return parts[0] == "apis" && parts[1] != "" && parts[2] != ""
	}
	return false
}

// rejectedRequest reports whether the request is one the proxy cannot
// forward: an impersonation header would have it speak for another
// identity, and a request that upgrades the connection changes it into
// something the proxy relays unchecked.
func rejectedRequest(r *http.Request) bool {
	for key := range r.Header {
		if strings.HasPrefix(key, "Impersonate-") {
			return true
		}
	}
	if r.Header.Get("Upgrade") != "" {
		return true
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}
