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
