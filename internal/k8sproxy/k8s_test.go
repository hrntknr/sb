package k8sproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

const testProxyPort = 16443

// testTarget builds a policy target granting the resources to one context.
func testTarget(context string, resources ...Resource) Target {
	return Target{Context: context, Resources: resources}
}

// testResource builds a core-group resource rule: verbs on resource in
// namespace ("*" is all namespaces).
func testResource(resource, namespace string, verbs ...string) Resource {
	return Resource{Group: "", Resource: resource, Namespace: namespace, Verbs: verbs}
}

// testPolicy builds a policy granting get/list/watch on core pods in
// namespace default for the named contexts: the shape the serve tests
// need, every request they make is covered by it.
func testPolicy(contexts ...string) Targets {
	targets := make(Targets, 0, len(contexts))
	for _, context := range contexts {
		targets = append(targets, testTarget(context, testResource("pods", "default", "get", "list", "watch")))
	}
	return targets
}

// allowsClassified classifies the request as the API server would and
// reports whether the policy permits it for context.
func allowsClassified(t *testing.T, targets Targets, context, method, path, query string) bool {
	t.Helper()
	info, err := classifyRequest(method, path, query)
	if err != nil {
		t.Fatalf("classifyRequest(%q, %q) error = %v", method, path, err)
	}
	return targets.Allows(context, info)
}

// TestTargetsAllowsClassifiedRequests covers the strict classification:
// what the API server would authorize decides what the proxy forwards.
// The verbs of a granted resource are enumerated, pods does not inherit
// to pods/log, and unknown or non-granted operations are rejected.
func TestTargetsAllowsClassifiedRequests(t *testing.T) {
	targets := Targets{
		testTarget("dev",
			testResource("pods", "default", "get", "list", "watch"),
		),
		testTarget("prod",
			testResource("pods/log", "default", "get"),
		),
	}

	tests := []struct {
		name, context, method, path, query string
		want                               bool
	}{
		// dev: the enumerated verbs on the granted resource
		{"dev get pod", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx", "", true},
		{"dev list pods", "dev", http.MethodGet, "/api/v1/namespaces/default/pods", "", true},
		{"dev list pods by name selector", "dev", http.MethodGet, "/api/v1/namespaces/default/pods", "fieldSelector=metadata.name%3Dnginx", true},
		{"dev watch pods", "dev", http.MethodGet, "/api/v1/namespaces/default/pods", "watch=true", true},
		// pods does not inherit to pods/log
		{"dev get pod log (no inheritance)", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/log", "", false},
		{"dev get pod log follow (no inheritance)", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/log", "follow=true", false},
		// unlisted operations are not granted
		{"dev create pod", "dev", http.MethodPost, "/api/v1/namespaces/default/pods", "", false},
		{"dev delete pods", "dev", http.MethodDelete, "/api/v1/namespaces/default/pods", "", false},
		{"dev patch pod", "dev", http.MethodPatch, "/api/v1/namespaces/default/pods/nginx", "", false},
		{"dev exec", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/exec", "", false},
		{"dev attach", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/attach", "", false},
		{"dev portforward", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/portforward", "", false},
		{"dev proxy subresource", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/proxy", "", false},
		{"dev node proxy", "dev", http.MethodGet, "/api/v1/nodes/node-1/proxy/stats", "", false},
		{"dev create self subject access review", "dev", http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "", false},
		// namespace restrictions
		{"dev other namespace", "dev", http.MethodGet, "/api/v1/namespaces/other/pods/nginx", "", false},
		{"dev all-namespaces list (not \"*\")", "dev", http.MethodGet, "/api/v1/pods", "", false},
		{"dev all-namespaces list of logs (not \"*\")", "dev", http.MethodGet, "/api/v1/pods/nginx/log", "", false},
		{"dev cluster-scoped (no scope rule)", "dev", http.MethodGet, "/api/v1/nodes", "", false},
		// discovery paths: GET only, fixed paths
		{"dev discovery /api", "dev", http.MethodGet, "/api", "", true},
		{"dev discovery /api/v1", "dev", http.MethodGet, "/api/v1", "", true},
		{"dev discovery /apis", "dev", http.MethodGet, "/apis", "", true},
		{"dev discovery /version", "dev", http.MethodGet, "/version", "", true},
		{"dev discovery /openapi/v2", "dev", http.MethodGet, "/openapi/v2", "", true},
		{"dev discovery POST /api", "dev", http.MethodPost, "/api", "", false},
		{"dev discovery /healthz", "dev", http.MethodGet, "/healthz", "", false},
		{"dev discovery /metrics", "dev", http.MethodGet, "/metrics", "", false},
		// prod: pods/log with get only
		{"prod get pod log", "prod", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/log", "", true},
		{"prod get pod log follow", "prod", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/log", "follow=true", true},
		{"prod list pods", "prod", http.MethodGet, "/api/v1/namespaces/default/pods", "", false},
		{"prod get pods", "prod", http.MethodGet, "/api/v1/namespaces/default/pods", "", false},
		// unknown group
		{"dev apps group", "dev", http.MethodGet, "/apis/apps/v1/namespaces/default/deployments", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allowsClassified(t, targets, tt.context, tt.method, tt.path, tt.query); got != tt.want {
				t.Fatalf("Allows(%s %s%s) = %v, want %v", tt.method, tt.path, querySuffix(tt.query), got, tt.want)
			}
		})
	}
}

func querySuffix(query string) string {
	if query == "" {
		return ""
	}
	return "?" + query
}

// TestTargetsAllNamespacesAndClusterScope covers the namespace forms: a
// namespaced rule covers one namespace, "*" covers every namespace and the
// all-namespaces list, and scope: cluster covers the cluster-scoped
// requests instead of a namespace.
func TestTargetsAllNamespacesAndClusterScope(t *testing.T) {
	targets := Targets{
		testTarget("dev",
			testResource("pods", "*", "get", "list"),
			Resource{Group: "", Resource: "namespaces", Scope: "cluster", Verbs: []string{"get", "list"}},
		),
		testTarget("prod",
			testResource("pods", "default", "get", "list"),
		),
	}

	tests := []struct {
		name, context, method, path string
		want                        bool
	}{
		// dev: "*" covers every namespace and the all-namespaces list
		{"dev pods in default", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx", true},
		{"dev pods in other", "dev", http.MethodGet, "/api/v1/namespaces/other/pods/nginx", true},
		{"dev all-namespaces list", "dev", http.MethodGet, "/api/v1/pods", true},
		// dev: scope cluster covers the cluster-scoped collection and
		// the named get alike. The namespace of the path (the
		// namespaces collection is named under
		// /api/v1/namespaces/<name>) is the parsing, not a scope: the
		// resource's scope decides, not the namespace it came on.
		{"dev list namespaces (cluster-scoped)", "dev", http.MethodGet, "/api/v1/namespaces", true},
		{"dev get one named namespace", "dev", http.MethodGet, "/api/v1/namespaces/foo", true},
		// prod: one named namespace only
		{"prod pods in default", "prod", http.MethodGet, "/api/v1/namespaces/default/pods/nginx", true},
		{"prod pods in other", "prod", http.MethodGet, "/api/v1/namespaces/other/pods/nginx", false},
		{"prod all-namespaces list", "prod", http.MethodGet, "/api/v1/pods", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allowsClassified(t, targets, tt.context, tt.method, tt.path, ""); got != tt.want {
				t.Fatalf("Allows(%s %s) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

// TestTargetsIsolateSameClusterDifferentContexts covers the context
// partition: two contexts pointing at the same cluster stay isolated, the
// rules of one context never apply to another, and matching a context name
// is exact.
func TestTargetsIsolateSameClusterDifferentContexts(t *testing.T) {
	// Both contexts point at the same cluster; dev grants pods, prod
	// grants pods/log only.
	targets := Targets{
		testTarget("dev", testResource("pods", "default", "get", "list", "watch")),
		testTarget("prod", testResource("pods/log", "default", "get")),
	}

	tests := []struct {
		name, context, path string
		want                bool
	}{
		{"dev list pods", "dev", "/api/v1/namespaces/default/pods", true},
		{"dev get pod log (no inheritance from prod)", "dev", "/api/v1/namespaces/default/pods/nginx/log", false},
		{"prod list pods (no inheritance from dev)", "prod", "/api/v1/namespaces/default/pods", false},
		{"prod get pod log", "prod", "/api/v1/namespaces/default/pods/nginx/log", true},
		{"prod get pod log (not case-identical)", "Prod", "/api/v1/namespaces/default/pods/nginx/log", false},
		{"unknown context", "stage", "/api/v1/namespaces/default/pods", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allowsClassified(t, targets, tt.context, http.MethodGet, tt.path, ""); got != tt.want {
				t.Fatalf("Allows(%s %s) = %v, want %v", http.MethodGet, tt.path, got, tt.want)
			}
		})
	}
}

func TestEmptyTargetsDenyAll(t *testing.T) {
	var targets Targets
	tests := []struct{ context, path string }{
		{"pear", "/api/v1/namespaces/default/pods"},
		{"pear", "/api"},
		{"pear", "/healthz"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if allowsClassified(t, targets, tt.context, http.MethodGet, tt.path, "") {
				t.Fatalf("empty targets allowed (%q, %q)", tt.context, tt.path)
			}
		})
	}
}

func TestSetTargetsUpdatesPolicy(t *testing.T) {
	proxy := New(testPolicy("dev"), "proxy.local")
	if !proxy.allows("dev", mustClassify(t, http.MethodGet, "/api/v1/namespaces/default/pods", "")) {
		t.Fatal("initial target should be allowed")
	}

	proxy.SetTargets(testPolicy("prod"))

	if proxy.allows("dev", mustClassify(t, http.MethodGet, "/api/v1/namespaces/default/pods", "")) {
		t.Fatal("old context should be denied after SetTargets")
	}
	if !proxy.allows("prod", mustClassify(t, http.MethodGet, "/api/v1/namespaces/default/pods", "")) {
		t.Fatal("new context should be allowed after SetTargets")
	}
}

// mustClassify classifies for the policy checks.
func mustClassify(t *testing.T, method, path, query string) *apirequest.RequestInfo {
	t.Helper()
	info, err := classifyRequest(method, path, query)
	if err != nil {
		t.Fatalf("classifyRequest(%q, %q) error = %v", method, path, err)
	}
	return info
}

// TestClassifyRequest covers the classification: the proxy authorizes
// what the API server would authorize for the same request.
func TestClassifyRequest(t *testing.T) {
	tests := []struct {
		name, method, path, query                                        string
		wantVerb, wantResource, wantSubresource, wantNamespace, wantName string
		wantResourceRequest                                              bool
	}{
		// Regular resources: get on a named object, list and watch on
		// collections (name empty turns get into list, watch comes
		// from the query).
		{"get pod", http.MethodGet, "/api/v1/namespaces/default/pods/nginx", "", "get", "pods", "", "default", "nginx", true},
		{"list pods", http.MethodGet, "/api/v1/namespaces/default/pods", "", "list", "pods", "", "default", "", true},
		{"watch pods", http.MethodGet, "/api/v1/namespaces/default/pods", "watch=true", "watch", "pods", "", "default", "", true},
		{"create pod", http.MethodPost, "/api/v1/namespaces/default/pods", "", "create", "pods", "", "default", "", true},
		// Subresources: log with a name, the watch path verb.
		{"get pod log", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/log", "", "get", "pods", "log", "default", "nginx", true},
		{"get pod log follow", http.MethodGet, "/api/v1/namespaces/default/pods/nginx/log", "follow=true", "get", "pods", "log", "default", "nginx", true},
		{"watch path prefix", http.MethodGet, "/api/v1/watch/namespaces/default/pods", "", "watch", "pods", "", "default", "", true},
		{"watch path all namespaces", http.MethodGet, "/api/v1/watch/pods", "", "watch", "pods", "", "", "", true},
		// Cluster-scoped and all-namespaces requests carry no namespace.
		{"list nodes", http.MethodGet, "/api/v1/nodes", "", "list", "nodes", "", "", "", true},
		{"list all namespaces pods", http.MethodGet, "/api/v1/pods", "", "list", "pods", "", "", "", true},
		// Non-resource requests: the fixed discovery paths only.
		{"discovery /api", http.MethodGet, "/api", "", "get", "", "", "", "", false},
		{"discovery /healthz", http.MethodGet, "/healthz", "", "get", "", "", "", "", false},
		{"group discovery", http.MethodGet, "/apis/apps/v1", "", "get", "", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := classifyRequest(tt.method, tt.path, tt.query)
			if err != nil {
				t.Fatalf("classifyRequest(%q, %q) error = %v", tt.method, tt.path, err)
			}
			if info.Verb != tt.wantVerb || info.Resource != tt.wantResource || info.Subresource != tt.wantSubresource {
				t.Fatalf("classifyRequest(%q, %q) verb/resource/subresource = %q/%q/%q, want %q/%q/%q",
					tt.method, tt.path, info.Verb, info.Resource, info.Subresource, tt.wantVerb, tt.wantResource, tt.wantSubresource)
			}
			if info.Namespace != tt.wantNamespace || info.Name != tt.wantName {
				t.Fatalf("classifyRequest(%q, %q) namespace/name = %q/%q, want %q/%q",
					tt.method, tt.path, info.Namespace, info.Name, tt.wantNamespace, tt.wantName)
			}
			if info.IsResourceRequest != tt.wantResourceRequest {
				t.Fatalf("classifyRequest(%q, %q) IsResourceRequest = %v, want %v", tt.method, tt.path, info.IsResourceRequest, tt.wantResourceRequest)
			}
		})
	}
}

// TestAllowedDiscoveryPath covers the fixed discovery paths a
// non-resource GET may take: /api, /apis, the core /api/v1, the discovery
// of a group, openapi, and the version endpoint. Everything else —
// /healthz, /metrics, arbitrary paths — is not granted.
func TestAllowedDiscoveryPath(t *testing.T) {
	allowed := []string{"/api", "/apis", "/api/v1", "/apis/apps/v1", "/version", "/openapi/v2", "/openapi/v3"}
	for _, path := range allowed {
		if !allowedDiscoveryPath(path) {
			t.Fatalf("allowedDiscoveryPath(%q) = false, want true", path)
		}
	}
	denied := []string{"/", "/api/v2", "/apis/apps", "/healthz", "/healthz/ready", "/metrics", "/openapi", "/openapi/v3/foo", "/logs", "/zzz"}
	for _, path := range denied {
		if allowedDiscoveryPath(path) {
			t.Fatalf("allowedDiscoveryPath(%q) = true, want false", path)
		}
	}
}

// TestRejectedRequest covers the requests the proxy cannot forward: an
// impersonation header would have it speak for another identity, and an
// upgraded connection is something it relays unchecked.
func TestRejectedRequest(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "https://proxy.local/dev/api", nil)
	if rejectedRequest(plain) {
		t.Fatal("a plain request was rejected")
	}

	tests := []struct {
		name, key, value string
	}{
		{"impersonation header", "Impersonate-User", "alice"},
		{"impersonation group header", "Impersonate-Group", "system:masters"},
		{"upgrade header", "Upgrade", "SPDY/3.0"},
		{"connection upgrade", "Connection", "keep-alive, Upgrade"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://proxy.local/dev/api/v1/namespaces/default/pods/nginx/log", nil)
			req.Header.Set(tt.key, tt.value)
			if !rejectedRequest(req) {
				t.Fatalf("rejectedRequest() = false for %s: %s", tt.key, tt.value)
			}
		})
	}
}

func TestUpstreamRequestPath(t *testing.T) {
	tests := []struct {
		path, context        string
		wantDecoded, wantRaw string
		wantWrong, wantOK    bool
	}{
		// The prefix names the context: the token's context.
		{"/dev/api/v1/namespaces/default/pods", "dev", "/api/v1/namespaces/default/pods", "/api/v1/namespaces/default/pods", false, true},
		{"/dev/api", "dev", "/api", "/api", false, true},
		{"/team%2Fdev/api/v1/namespaces/default/pods/nginx/log", "team/dev", "/api/v1/namespaces/default/pods/nginx/log", "/api/v1/namespaces/default/pods/nginx/log", false, true},
		// No API path after the context prefix.
		{"/dev", "dev", "", "", false, false},
		{"/", "dev", "", "", false, false},
		// Non-API paths pass through and are classified as non-resource.
		{"/dev/foo", "dev", "/foo", "/foo", false, true},
		{"/dev/api/../secrets", "dev", "/api/../secrets", "/api/../secrets", false, true},
		// The token is used on another context's URL.
		{"/prod/api", "dev", "", "", true, false},
		{"/dev/api", "prod", "", "", true, false},
		// Another context on the same URL prefix.
		{"/team%2Fdev/api", "team%2Fdev", "", "", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			u, err := url.ParseRequestURI("https://proxy.local" + tt.path)
			if err != nil {
				t.Fatalf("ParseRequestURI() error = %v", err)
			}
			decoded, raw, wrong, ok := upstreamRequestPath(u, tt.context)
			if decoded != tt.wantDecoded || raw != tt.wantRaw || wrong != tt.wantWrong || ok != tt.wantOK {
				t.Fatalf("upstreamRequestPath(%q, %q) = %q, %q, %v, %v; want %q, %q, %v, %v",
					tt.path, tt.context, decoded, raw, wrong, ok, tt.wantDecoded, tt.wantRaw, tt.wantWrong, tt.wantOK)
			}
		})
	}
}

func TestRenderKubeconfig(t *testing.T) {
	kubeconfig, _, err := New(nil, "proxy.local").renderKubeconfig(testProxyPort, []kubeconfigContext{{Name: "pear"}, {Name: "test"}}, "test")
	if err != nil {
		t.Fatalf("renderKubeconfig() error = %v", err)
	}

	text := string(kubeconfig)
	if !strings.Contains(text, "server: https://proxy.local:16443/pear") {
		t.Fatalf("kubeconfig does not contain pear proxy path: %q", text)
	}
	if !strings.Contains(text, "server: https://proxy.local:16443/test") {
		t.Fatalf("kubeconfig does not contain test proxy path: %q", text)
	}
	if !strings.Contains(text, "certificate-authority-data: ") {
		t.Fatalf("kubeconfig does not embed the proxy CA: %q", text)
	}
	if strings.Contains(text, "insecure-skip-tls-verify") {
		t.Fatalf("kubeconfig disables TLS verification: %q", text)
	}
	if strings.Count(text, "token:") != 2 {
		t.Fatalf("kubeconfig = %q", text)
	}
	if strings.Contains(text, "proxy-") {
		t.Fatalf("kubeconfig renamed entries: %q", text)
	}
	if !strings.Contains(text, "current-context: test") {
		t.Fatalf("kubeconfig = %q", text)
	}
}

func TestRenderKubeconfigEscapesContextInProxyPath(t *testing.T) {
	kubeconfig, _, err := New(nil, "proxy.local").renderKubeconfig(testProxyPort, []kubeconfigContext{{Name: "team/dev"}}, "team/dev")
	if err != nil {
		t.Fatalf("renderKubeconfig() error = %v", err)
	}

	text := string(kubeconfig)
	if !strings.Contains(text, "server: https://proxy.local:16443/team%2Fdev") {
		t.Fatalf("kubeconfig does not contain escaped proxy path: %q", text)
	}
}

func TestRenderKubeconfigIncludesNamespace(t *testing.T) {
	kubeconfig, _, err := New(nil, "proxy.local").renderKubeconfig(testProxyPort, []kubeconfigContext{
		{Name: "dev", Namespace: "apps"},
	}, "dev")
	if err != nil {
		t.Fatalf("renderKubeconfig() error = %v", err)
	}

	text := string(kubeconfig)
	if !strings.Contains(text, "namespace: apps") {
		t.Fatalf("kubeconfig = %q", text)
	}
}

func TestRenderKubeconfigWithoutContexts(t *testing.T) {
	kubeconfig, _, err := New(nil, "proxy.local").renderKubeconfig(testProxyPort, nil, "")
	if err != nil {
		t.Fatalf("renderKubeconfig() error = %v", err)
	}
	text := string(kubeconfig)
	for _, want := range []string{"clusters: []", "users: []", "contexts: []"} {
		if !strings.Contains(text, want) {
			t.Fatalf("kubeconfig = %q, want %q", text, want)
		}
	}
}

func TestSyncConfigReadsContextsFromUpstreamKubeconfig(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev")
	proxy := New(testPolicy("dev"), "proxy.local")
	cancel := runSyncConfig(t, proxy, testProxyPort, dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "server: https://proxy.local:16443/dev")
	})

	// prod enters the next session: a fresh proxy and its initial
	// issuance read the changed source there.
	writeSourceKubeconfig(t, sourcePath, "dev", "prod")
	proxy2 := New(testPolicy("dev", "prod"), "proxy.local")
	cancel2 := runSyncConfig(t, proxy2, testProxyPort, dir)
	defer cancel2()
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "server: https://proxy.local:16443/prod")
	})
}

func TestSyncConfigUsesUpstreamCurrentContextInitially(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "prod", "dev")
	cancel := runSyncConfig(t, New(testPolicy("prod", "dev"), "proxy.local"), testProxyPort, dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "current-context: prod")
	})
}

func TestSyncConfigKeepsInnerCurrentContext(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "prod", "dev")

	// Session 1: the initial issuance renders with the source's current
	// context (prod).
	proxy := New(testPolicy("prod", "dev"), "proxy.local")
	cancel := runSyncConfig(t, proxy, testProxyPort, dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "current-context: prod")
	})

	// The user switches the current context inside the generated
	// kubeconfig.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content = []byte(strings.Replace(string(content), "current-context: prod", "current-context: dev", 1))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// The next session: its initial issuance reads the inner override
	// and keeps it.
	proxy2 := New(testPolicy("prod", "dev"), "proxy.local")
	cancel2 := runSyncConfig(t, proxy2, testProxyPort, dir)
	defer cancel2()
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "current-context: dev")
	})
}

func TestSyncConfigUsesUpstreamNamespaceInitially(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfigWithNamespaces(t, sourcePath, map[string]string{"dev": "apps"}, "dev")
	cancel := runSyncConfig(t, New(testPolicy("dev"), "proxy.local"), testProxyPort, dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "namespace: apps")
	})
}

func TestSyncConfigKeepsInnerNamespace(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfigWithNamespaces(t, sourcePath, map[string]string{"dev": "apps"}, "dev")

	// Session 1: the initial issuance renders with the source's
	// namespace (apps).
	proxy := New(testPolicy("dev"), "proxy.local")
	cancel := runSyncConfig(t, proxy, testProxyPort, dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "namespace: apps")
	})

	// The user overrides the namespace inside the generated kubeconfig.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content = []byte(strings.Replace(string(content), "namespace: apps", "namespace: local", 1))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// The next session: its initial issuance reads the inner override
	// and keeps it, even against the source's namespace.
	proxy2 := New(testPolicy("dev"), "proxy.local")
	cancel2 := runSyncConfig(t, proxy2, testProxyPort, dir)
	defer cancel2()
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "namespace: local")
	})
}

func TestSyncConfigEmptyDirWritesUnderWorkingDir(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore Chdir() error = %v", err)
		}
	}()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev")
	cancel := runSyncConfig(t, New(testPolicy("dev"), "proxy.local"), testProxyPort, "")
	defer cancel()

	waitFor(t, func() bool {
		_, err := os.Stat(filepath.Join(dir, ".kube", "config"))
		return err == nil
	})
}

func TestServeRejectsPathWithoutUpstreamAPIPath(t *testing.T) {
	proxy := New(testPolicy("dev"), "localhost")
	proxy.tokens = map[string]string{"downstream-token": "dev"}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.local/dev", nil)
	req.Header.Set("Authorization", "Bearer downstream-token")
	rec := httptest.NewRecorder()

	proxy.serveHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// Regression: a path the API server's classification reads past the end
// of the resource it names — a further segment after the subresource, an
// escape that decodes to a separator, a version the core group does not
// have, a doubled separator at the context or at the end — must not
// reach the upstream. With pods/log granted, all of them pass as
// pods/log get or pods list and are forwarded.
func TestServeRejectsMalformedAPIPath(t *testing.T) {
	hits := int32(0)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeUsableSourceKubeconfig(t, sourcePath, upstream.URL)

	proxy := New(Targets{testTarget("dev",
		testResource("pods/log", "default", "get"),
		testResource("pods", "default", "get", "list", "watch"),
	)}, "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for _, path := range []string{
		// a further segment past the subresource: the API server would
		// read past the end of the log path
		"/dev/api/v1/namespaces/default/pods/nginx/log/extra",
		// an escape that decodes to a separator: the raw path would be
		// read as the log path upstream
		"/dev/api/v1/namespaces/default/pods/nginx%2Flog",
		// a version the core group does not have: it classifies as a
		// pods list
		"/dev/api/unknown/namespaces/default/pods",
		// a doubled separator before the API path: an empty segment the
		// classification would read as none
		"/dev//api/v1/namespaces/default/pods",
		// a doubled separator past the resource: an empty segment at
		// the end
		"/dev/api/v1/namespaces/default/pods//",
		// a trailing separator: an empty final segment
		"/dev/api/v1/namespaces/default/pods/",
	} {
		req, err := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+path, nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		req.Header.Set("Authorization", "Bearer downstream-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do() error = %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("malformed path %q status = %d, want %d (rejected before the upstream)", path, resp.StatusCode, http.StatusBadRequest)
		}
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("malformed paths reached the upstream %d times", hits)
	}
}

func TestServeRejectsInvalidToken(t *testing.T) {
	proxy := New(testPolicy("dev"), "localhost")
	proxy.tokens = map[string]string{"downstream-token": "dev"}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.local/dev/api", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()

	proxy.serveHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestServeProxiesToUpstreamContext(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api" {
			t.Fatalf("upstream path = %q, want /api", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer upstream-token" {
			t.Fatalf("upstream Authorization = %q, got %q", "Bearer upstream-token", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeUsableSourceKubeconfig(t, sourcePath, upstream.URL)

	proxy := New(testPolicy("dev"), "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	req, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/dev/api", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer downstream-token")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req.URL.Scheme = "https"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

// Regression: the resolved API server URL's base path is kept when
// forwarding. A server under https://gateway.example/k8s receives
// /k8s/api/..., not /api/...: without the base path the request would
// go to another route on the gateway host, credentials included. The
// raw form the upstream sees is the joined escape — the base's escapes
// included — so a base behind an escaped separator stays itself.
func TestServeProxiesToUpstreamBasePath(t *testing.T) {
	// wantURI/wantLog: the raw forms the upstream server must see on
	// the discovery path and the log path.
	tests := []struct {
		name    string
		base    string // the base path of the server URL in the source kubeconfig
		wantURI string
		wantLog string
	}{
		{"no base", "", "/api", "/api/v1/namespaces/default/pods/nginx/log"},
		{"plain base", "/k8s", "/k8s/api", "/k8s/api/v1/namespaces/default/pods/nginx/log"},
		{"trailing slash", "/k8s/", "/k8s/api", "/k8s/api/v1/namespaces/default/pods/nginx/log"},
		{"escaped separator", "/k8s%2F", "/k8s%2F/api", "/k8s%2F/api/v1/namespaces/default/pods/nginx/log"},
		{"escaped separator and suffix", "/k8s%2Ftenant", "/k8s%2Ftenant/api", "/k8s%2Ftenant/api/v1/namespaces/default/pods/nginx/log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The raw forms the upstream saw: the request URI as it went
			// over the wire, and the server's own escape of it. The
			// pair must be the joined escape, not a re-escape of a
			// differently joined path.
			type saw struct{ requestURI, escapedPath string }
			seen := make(chan saw, 2)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- saw{r.RequestURI, r.URL.EscapedPath()}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()

			sourcePath := filepath.Join(t.TempDir(), "config")
			t.Setenv("KUBECONFIG", sourcePath)
			writeUsableSourceKubeconfig(t, sourcePath, upstream.URL+tt.base)

			proxy := New(Targets{testTarget("dev",
				testResource("pods", "default", "get", "list", "watch"),
				testResource("pods/log", "default", "get"),
			)}, "localhost")
			if err := proxy.resolveConnections(); err != nil {
				t.Fatal(err)
			}
			proxy.tokens = map[string]string{"downstream-token": "dev"}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Listen() error = %v", err)
			}
			defer listener.Close()
			go func() {
				_ = proxy.Serve(listener)
			}()

			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			for _, path := range []string{
				// discovery under the base path
				"/dev/api",
				// a resource path under it
				"/dev/api/v1/namespaces/default/pods/nginx/log",
			} {
				req, err := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+path, nil)
				if err != nil {
					t.Fatalf("NewRequest() error = %v", err)
				}
				req.Header.Set("Authorization", "Bearer downstream-token")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Do() error = %v", err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					t.Fatalf("%s: status = %d, want %d", path, resp.StatusCode, http.StatusNoContent)
				}
			}
			if got := <-seen; got.requestURI != tt.wantURI || got.escapedPath != tt.wantURI {
				t.Fatalf("discovery path: requestURI = %q, escapedPath = %q, want %q", got.requestURI, got.escapedPath, tt.wantURI)
			}
			if got := <-seen; got.requestURI != tt.wantLog || got.escapedPath != tt.wantLog {
				t.Fatalf("log path: requestURI = %q, escapedPath = %q, want %q", got.requestURI, got.escapedPath, tt.wantLog)
			}
		})
	}
}

// Regression: two contexts pointing at the same cluster must stay isolated;
// the read-only prod context must not gain write access to the shared
// cluster.
func TestServeIsolatesSameClusterDifferentContexts(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer dev-upstream-token" {
			t.Errorf("upstream Authorization = %q, want dev upstream token", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSharedClusterSourceKubeconfig(t, sourcePath, upstream.URL)

	proxy := New(Targets{
		testTarget("dev", testResource("pods", "default", "create")),
		testTarget("prod", testResource("pods", "default", "get", "list", "watch")),
	}, "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"dev-token": "dev", "prod-token": "prod"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	req, err := http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/dev/api/v1/namespaces/default/pods", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer dev-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("dev Do() error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("dev status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	req, err = http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/prod/api/v1/namespaces/default/pods", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer prod-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("prod Do() error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("prod status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// TestServeProxiesKubectlLogs covers the kubectl logs flow at the protocol
// level: an explicitly granted pods/log get passes (logs and logs -f),
// the stream stays open with further lines arriving before it ends,
// without the explicit grant the same request is denied — follow=true
// included — and a token of another context on the URL is rejected
// before the upstream.
func TestServeProxiesKubectlLogs(t *testing.T) {
	seen := make(chan string, 4)
	// gates release the open streams: the upstream waits for the
	// downstream to have read the first line before it sends the
	// second — the stream is still open, not ended, while the
	// downstream already received.
	gates := make(chan struct{}, 2)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.Path + "?" + r.URL.RawQuery
		fmt.Fprint(w, "first line\n")
		w.(http.Flusher).Flush()
		<-gates
		fmt.Fprint(w, "second line\n")
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSharedClusterSourceKubeconfig(t, sourcePath, upstream.URL)

	proxy := New(Targets{
		testTarget("dev",
			testResource("pods", "default", "get"),
			testResource("pods/log", "default", "get"),
		),
	}, "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev", "other-token": "prod"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	logsStatus := func(context, token, query string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/"+context+"/api/v1/namespaces/default/pods/nginx/log"+query, nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do() error = %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// granted: kubectl logs and kubectl logs -f both reach the upstream,
	// the stream relaying as it arrives: the first line is received
	// while the stream is open (the second has not been sent yet), the
	// second before the stream ends.
	for _, query := range []string{"", "?follow=true"} {
		req, err := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/dev/api/v1/namespaces/default/pods/nginx/log"+query, nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		req.Header.Set("Authorization", "Bearer downstream-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do() error = %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logs %q status = %d, want %d", query, resp.StatusCode, http.StatusOK)
		}
		body := bufio.NewReader(resp.Body)
		line, err := body.ReadString('\n')
		if err != nil || line != "first line\n" {
			t.Fatalf("first line was not received from the open stream: %q, %v", line, err)
		}
		// The downstream read the first line: release the stream.
		gates <- struct{}{}
		line, err = body.ReadString('\n')
		if line != "second line\n" || (err != nil && err != io.EOF) {
			t.Fatalf("second line was not received before the stream ended: %q, %v", line, err)
		}
		if got := <-seen; got != "/api/v1/namespaces/default/pods/nginx/log?"+strings.TrimPrefix(query, "?") {
			t.Fatalf("upstream request = %q, want the log path with %q", got, query)
		}
		resp.Body.Close()
	}

	// denied by policy: without the explicit pods/log rule both the
	// plain request and follow=true are denied
	proxy.SetTargets(Targets{testTarget("dev", testResource("pods", "default", "get"))})
	for _, query := range []string{"", "?follow=true"} {
		if got := logsStatus("dev", "downstream-token", query); got != http.StatusForbidden {
			t.Fatalf("logs %q status = %d, want %d (denied without pods/log)", query, got, http.StatusForbidden)
		}
	}

	// a token of another context on the URL is rejected before the upstream
	if got := logsStatus("dev", "other-token", ""); got != http.StatusForbidden {
		t.Fatalf("logs status with another context's token = %d, want %d", got, http.StatusForbidden)
	}
}

func TestServeProxiesWithOIDCAuthProvider(t *testing.T) {
	idToken := testIDToken(t, time.Now().Add(time.Hour))
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+idToken {
			t.Fatalf("upstream Authorization = %q, got %q", "Bearer "+idToken, got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeOIDCSourceKubeconfig(t, sourcePath, upstream.URL, idToken)

	proxy := New(testPolicy("dev"), "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	req, err := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/dev/api", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer downstream-token")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

// Regression: the proxy must not set the upstream Authorization itself —
// the transport's auth settings then refresh per request. With a token
// file, the new token is observed upstream after the file changes: the
// transport re-reads it (client-go's cached file source, a minute minus
// leeway after the first read).
func TestServeObservesTokenFileUpdates(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("old-upstream-token"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeTokenFileSourceKubeconfig(t, sourcePath, upstream.URL, tokenPath)

	proxy := New(testPolicy("dev"), "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	request := func() {
		t.Helper()
		requestKubeAPI(t, client, listener.Addr().String(), "dev", "downstream-token")
	}

	request()
	if got := <-seen; got != "Bearer old-upstream-token" {
		t.Fatalf("upstream Authorization = %q, want the file's initial token", got)
	}

	if err := os.WriteFile(tokenPath, []byte("new-upstream-token"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// The transport re-reads the file: within its cache period (a
	// minute minus leeway) the new token is observed upstream.
	deadline := time.Now().Add(90 * time.Second)
	for {
		request()
		if got := <-seen; got == "Bearer new-upstream-token" {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatal("the new token was not observed upstream")
		}
	}
}

func TestServeProxiesOIDCAuthProviderPerContext(t *testing.T) {
	adminToken := testIDTokenWithSubject(t, time.Now().Add(time.Hour), "admin")
	pfnToken := testIDTokenWithSubject(t, time.Now().Add(time.Hour), "pfn")
	seen := make(chan string, 2)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeOIDCMultiContextSourceKubeconfig(t, sourcePath, upstream.URL, adminToken, pfnToken)

	proxy := New(testPolicy("pfcp-yh1-01", "pfcp-pfn-yh1-01"), "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{
		"downstream-admin-token": "pfcp-yh1-01",
		"downstream-pfn-token":   "pfcp-pfn-yh1-01",
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	requestKubeAPI(t, client, listener.Addr().String(), "pfcp-pfn-yh1-01", "downstream-pfn-token")
	if got := <-seen; got != "Bearer "+pfnToken {
		t.Fatalf("first upstream Authorization = %q, want pfn token", got)
	}
	requestKubeAPI(t, client, listener.Addr().String(), "pfcp-yh1-01", "downstream-admin-token")
	if got := <-seen; got != "Bearer "+adminToken {
		t.Fatalf("second upstream Authorization = %q, want admin token", got)
	}
}

func TestServeRefreshesOIDCAuthProviderAndPersistsUpstreamConfig(t *testing.T) {
	refreshedToken := testIDTokenWithSubject(t, time.Now().Add(time.Hour), "refreshed")
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token_endpoint":%q}`, issuer.URL+"/token")
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if got := r.Form.Get("refresh_token"); got != "old-refresh" {
				t.Fatalf("refresh_token = %q, got %q", "old-refresh", got)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":"access","token_type":"Bearer","id_token":%q,"refresh_token":"new-refresh"}`, refreshedToken)
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()

	seen := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	issuerCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw})
	writeOIDCRefreshSourceKubeconfig(t, sourcePath, upstream.URL, issuer.URL, base64.StdEncoding.EncodeToString(issuerCA), testIDToken(t, time.Now().Add(-time.Hour)))

	proxy := New(testPolicy("dev"), "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	requestKubeAPI(t, client, listener.Addr().String(), "dev", "downstream-token")
	if got := <-seen; got != "Bearer "+refreshedToken {
		t.Fatalf("upstream Authorization = %q, want refreshed token", got)
	}
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "id-token: "+refreshedToken) {
		t.Fatalf("kubeconfig did not persist refreshed id-token: %q", text)
	}
	if !strings.Contains(text, "refresh-token: new-refresh") {
		t.Fatalf("kubeconfig did not persist refreshed refresh-token: %q", text)
	}
}

func TestServeUsesUpdatedOIDCAuthProviderConfig(t *testing.T) {
	oldToken := testIDTokenWithSubject(t, time.Now().Add(time.Hour), "old")
	newToken := testIDTokenWithSubject(t, time.Now().Add(time.Hour), "new")
	seen := make(chan string, 2)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeOIDCSourceKubeconfig(t, sourcePath, upstream.URL, oldToken)

	proxy := New(testPolicy("dev"), "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	requestKubeAPI(t, client, listener.Addr().String(), "dev", "downstream-token")
	if got := <-seen; got != "Bearer "+oldToken {
		t.Fatalf("first upstream Authorization = %q, want old token", got)
	}

	// The session's connection is fixed: the rewritten source does not
	// change the auth settings already resolved.
	writeOIDCSourceKubeconfig(t, sourcePath, upstream.URL, newToken)
	requestKubeAPI(t, client, listener.Addr().String(), "dev", "downstream-token")
	if got := <-seen; got != "Bearer "+oldToken {
		t.Fatalf("second upstream Authorization = %q, want the token fixed for the session", got)
	}

	// The next session resolves the auth settings anew: a fresh proxy
	// whose initial issuance resolves the rewritten source, and a
	// request made with what it issued — the generated kubeconfig's URL
	// and token — no internal state set by hand.
	// The session's own listener comes first, on a dynamic port: the
	// issuance names that port in the generated kubeconfig, and the
	// proxy serves on that listener for the request to reach it.
	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener2.Close()
	issueDir := t.TempDir()
	proxy2 := New(testPolicy("dev"), "localhost")
	cancel2 := runSyncConfig(t, proxy2, listener2.Addr().(*net.TCPAddr).Port, issueDir)
	defer cancel2()
	go func() {
		_ = proxy2.Serve(listener2)
	}()

	// The request made with what the session issued.
	kubeconfig2 := filepath.Join(issueDir, ".kube", "config")
	server := issuedServerURL(t, kubeconfig2)
	token2 := contextToken(t, kubeconfig2, "dev")
	req, err := http.NewRequest(http.MethodGet, server+"/api", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token2)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if got := <-seen; got != "Bearer "+newToken {
		t.Fatalf("third upstream Authorization = %q, want new token", got)
	}
}

func TestOIDCCacheHostIncludesContextAndAuthProviderConfig(t *testing.T) {
	base := oidcCacheHost("https://cluster.example", "ctx", map[string]string{"id-token": "a"})
	if got := oidcCacheHost("https://cluster.example", "other", map[string]string{"id-token": "a"}); got == base {
		t.Fatalf("oidcCacheHost did not include context")
	}
	if got := oidcCacheHost("https://cluster.example", "ctx", map[string]string{"id-token": "b"}); got == base {
		t.Fatalf("oidcCacheHost did not include auth-provider config")
	}
}

// Regression: the proxy certificate must cover the configured host so that
// clients verifying against the embedded CA succeed for non-localhost
// --host values (DNS names and IPs).
func TestCertificateCoversConfiguredHost(t *testing.T) {
	tests := []struct {
		host string
		dns  string
		ip   net.IP
	}{
		{host: "host.docker.internal", dns: "host.docker.internal"},
		{host: "192.0.2.10", ip: net.ParseIP("192.0.2.10")},
	}
	for _, tt := range tests {
		certificate, err := New(nil, tt.host).certificate()
		if err != nil {
			t.Fatalf("certificate() error = %v", err)
		}
		cert, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			t.Fatalf("ParseCertificate() error = %v", err)
		}
		if tt.dns != "" {
			found := false
			for _, name := range cert.DNSNames {
				if name == tt.dns {
					found = true
				}
			}
			if !found {
				t.Fatalf("certificate for %q lacks DNS SAN, got %v", tt.host, cert.DNSNames)
			}
		}
		if tt.ip != nil {
			found := false
			for _, ip := range cert.IPAddresses {
				if ip.Equal(tt.ip) {
					found = true
				}
			}
			if !found {
				t.Fatalf("certificate for %q lacks IP SAN, got %v", tt.host, cert.IPAddresses)
			}
		}
	}
}

// The generated kubeconfig embeds the proxy CA; a client verifying against
// it (instead of skipping verification) must succeed.
func TestServeTLSVerifiedAgainstEmbeddedCA(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeUsableSourceKubeconfig(t, sourcePath, upstream.URL)

	proxy := New(testPolicy("dev"), "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	content, _, err := proxy.renderKubeconfig(testProxyPort, []kubeconfigContext{{Name: "dev"}}, "dev")
	if err != nil {
		t.Fatalf("renderKubeconfig() error = %v", err)
	}
	var rendered kubeconfigFile
	if err := yaml.Unmarshal(content, &rendered); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	caPEM, err := base64.StdEncoding.DecodeString(rendered.Clusters[0].Cluster.CertificateAuthorityData)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("embedded CA is not a valid certificate")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	requestKubeAPI(t, client, listener.Addr().String(), "dev", "downstream-token")
}

// Regression: the session's issuance stays fixed. Source changes — a
// context removed, the source corrupted, the context swapped back in —
// must not change the issued tokens or the generated kubeconfig while
// the session runs; a change lands next session.
func TestSyncConfigKeepsIssuedTokensWhenSourceChanges(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev", "prod")

	proxy := New(testPolicy("dev", "prod"), "proxy.local")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan error, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- proxy.SyncConfig(ctx, testProxyPort, dir, ready)
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "server: https://proxy.local:16443/dev")
	})
	issued, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	devToken := contextToken(t, path, "dev")

	// assertFixed: whatever the source change, the issuance stays
	// fixed — the tokens and the file on disk do not change while the
	// session runs. The window lets a re-render land if one runs.
	assertFixed := func() {
		t.Helper()
		time.Sleep(500 * time.Millisecond)
		if got := contextToken(t, path, "dev"); got != devToken {
			t.Fatalf("the dev token changed: %q, want %q", got, devToken)
		}
		now, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if string(now) != string(issued) {
			t.Fatal("the generated kubeconfig was rewritten")
		}
		select {
		case err := <-errc:
			t.Fatalf("SyncConfig() ended: %v", err)
		default:
		}
	}

	// a permitted context disappears from the source: its token stays
	writeSourceKubeconfig(t, sourcePath, "prod")
	assertFixed()

	// the source becomes invalid YAML mid-save
	if err := os.WriteFile(sourcePath, []byte("apiVersion: v1\nkind: Config\ncontexts: ["), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assertFixed()

	// the context returns: a re-issue would replace the token
	writeSourceKubeconfig(t, sourcePath, "dev", "prod")
	assertFixed()

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("SyncConfig() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SyncConfig() did not stop")
	}
}

// contextToken reads the token issued for a context from a generated
// kubeconfig.
func contextToken(t *testing.T, path, context string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var rendered kubeconfigFile
	if err := yaml.Unmarshal(content, &rendered); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	for _, user := range rendered.Users {
		if user.Name == context {
			return user.User.Token
		}
	}
	return ""
}

// issuedServerURL reads the server URL the generated kubeconfig at
// path gives its current context.
func issuedServerURL(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var rendered kubeconfigFile
	if err := yaml.Unmarshal(content, &rendered); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	for _, context := range rendered.Contexts {
		if context.Name != rendered.CurrentContext {
			continue
		}
		for _, cluster := range rendered.Clusters {
			if cluster.Name == context.Context.Cluster {
				return cluster.Cluster.Server
			}
		}
	}
	t.Fatalf("no server URL for the current context %q", rendered.CurrentContext)
	return ""
}

func TestRenderKubeconfigIPv6Host(t *testing.T) {
	kubeconfig, _, err := New(nil, "::1").renderKubeconfig(testProxyPort, []kubeconfigContext{{Name: "dev"}}, "dev")
	if err != nil {
		t.Fatalf("renderKubeconfig() error = %v", err)
	}
	if !strings.Contains(string(kubeconfig), "server: https://[::1]:16443/dev") {
		t.Fatalf("kubeconfig does not bracket IPv6 host: %q", kubeconfig)
	}
}

// runSyncConfig starts the proxy's session issuance on port: the port
// the issuance names in the generated kubeconfig. A test that serves
// holds its own listener on that port — the proxy serves there; the
// rest only read what the issuance wrote.
func runSyncConfig(t *testing.T, proxy *Proxy, port int, dir string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	ready := make(chan error, 1)
	go func() {
		errc <- proxy.SyncConfig(ctx, port, dir, ready)
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("SyncConfig() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatalf("SyncConfig() did not stop")
		}
	})
	return cancel
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition was not met")
}

func writeSourceKubeconfig(t *testing.T, path string, contexts ...string) {
	t.Helper()
	namespaces := make(map[string]string, len(contexts))
	for _, context := range contexts {
		namespaces[context] = ""
	}
	writeSourceKubeconfigWithNamespaces(t, path, namespaces, contexts...)
}

func writeSourceKubeconfigWithNamespaces(t *testing.T, path string, namespaces map[string]string, contexts ...string) {
	t.Helper()
	// The source resolves: each context references a cluster and a user
	// entry, so a session start resolving the policy's contexts succeeds
	// without a live upstream (resolution builds the transport only).
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\nclusters:\n")
	b.WriteString("- name: shared\n  cluster:\n    server: https://upstream.example.test\n")
	b.WriteString("users:\n")
	b.WriteString("- name: shared\n  user:\n    token: upstream-token\n")
	b.WriteString("contexts:\n")
	for _, context := range contexts {
		b.WriteString("- name: ")
		b.WriteString(context)
		if namespace := namespaces[context]; namespace != "" {
			b.WriteString("\n  context:\n    cluster: shared\n    user: shared\n    namespace: ")
			b.WriteString(namespace)
			b.WriteString("\n")
		} else {
			b.WriteString("\n  context:\n    cluster: shared\n    user: shared\n")
		}
	}
	if len(contexts) > 0 {
		b.WriteString("current-context: ")
		b.WriteString(contexts[0])
		b.WriteString("\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writeUsableSourceKubeconfig(t *testing.T, path, server string) {
	t.Helper()
	content := "apiVersion: v1\nkind: Config\nclusters:\n" +
		"- name: dev\n  cluster:\n    server: " + server + "\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n" +
		"- name: dev\n  user:\n    token: upstream-token\n" +
		"contexts:\n" +
		"- name: dev\n  context:\n    cluster: dev\n    user: dev\n" +
		"current-context: dev\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writeSharedClusterSourceKubeconfig(t *testing.T, path, server string) {
	t.Helper()
	content := "apiVersion: v1\nkind: Config\nclusters:\n" +
		"- name: shared\n  cluster:\n    server: " + server + "\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n" +
		"- name: dev\n  user:\n    token: dev-upstream-token\n" +
		"- name: prod\n  user:\n    token: prod-upstream-token\n" +
		"contexts:\n" +
		"- name: dev\n  context:\n    cluster: shared\n    user: dev\n" +
		"- name: prod\n  context:\n    cluster: shared\n    user: prod\n" +
		"current-context: dev\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writeOIDCSourceKubeconfig(t *testing.T, path, server, idToken string) {
	t.Helper()
	content := "apiVersion: v1\nkind: Config\nclusters:\n" +
		"- name: dev\n  cluster:\n    server: " + server + "\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n" +
		"- name: dev\n  user:\n    auth-provider:\n      name: oidc\n      config:\n" +
		"        client-id: test-client\n" +
		"        id-token: " + idToken + "\n" +
		"        idp-issuer-url: https://issuer.example.test\n" +
		"contexts:\n" +
		"- name: dev\n  context:\n    cluster: dev\n    user: dev\n" +
		"current-context: dev\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

// writeTokenFileSourceKubeconfig writes a source kubeconfig whose user
// authenticates by a token file: the connection's transport reads it per
// request (a client-go cached file source).
func writeTokenFileSourceKubeconfig(t *testing.T, path, server, tokenPath string) {
	t.Helper()
	content := "apiVersion: v1\nkind: Config\nclusters:\n" +
		"- name: dev\n  cluster:\n    server: " + server + "\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n" +
		"- name: dev\n  user:\n    tokenFile: " + tokenPath + "\n" +
		"contexts:\n" +
		"- name: dev\n  context:\n    cluster: dev\n    user: dev\n" +
		"current-context: dev\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writeOIDCRefreshSourceKubeconfig(t *testing.T, path, server, issuer, issuerCA, idToken string) {
	t.Helper()
	content := "apiVersion: v1\nkind: Config\nclusters:\n" +
		"- name: dev\n  cluster:\n    server: " + server + "\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n" +
		"- name: dev\n  user:\n    auth-provider:\n      name: oidc\n      config:\n" +
		"        client-id: test-client\n" +
		"        id-token: " + idToken + "\n" +
		"        idp-certificate-authority-data: " + issuerCA + "\n" +
		"        idp-issuer-url: " + issuer + "\n" +
		"        refresh-token: old-refresh\n" +
		"contexts:\n" +
		"- name: dev\n  context:\n    cluster: dev\n    user: dev\n" +
		"current-context: dev\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writeOIDCMultiContextSourceKubeconfig(t *testing.T, path, server, adminToken, pfnToken string) {
	t.Helper()
	content := "apiVersion: v1\nkind: Config\nclusters:\n" +
		"- name: shared\n  cluster:\n    server: " + server + "\n" +
		"    insecure-skip-tls-verify: true\n" +
		"users:\n" +
		"- name: admin\n  user:\n    auth-provider:\n      name: oidc\n      config:\n" +
		"        client-id: test-client\n" +
		"        id-token: " + adminToken + "\n" +
		"        idp-issuer-url: https://issuer.example.test\n" +
		"- name: pfn\n  user:\n    auth-provider:\n      name: oidc\n      config:\n" +
		"        client-id: test-client\n" +
		"        id-token: " + pfnToken + "\n" +
		"        idp-issuer-url: https://issuer.example.test\n" +
		"contexts:\n" +
		"- name: pfcp-yh1-01\n  context:\n    cluster: shared\n    user: admin\n" +
		"- name: pfcp-pfn-yh1-01\n  context:\n    cluster: shared\n    user: pfn\n" +
		"current-context: pfcp-yh1-01\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func requestKubeAPI(t *testing.T, client *http.Client, addr, context, token string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/"+context+"/api", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func testIDToken(t *testing.T, expiry time.Time) string {
	return testIDTokenWithSubject(t, expiry, "")
}

func testIDTokenWithSubject(t *testing.T, expiry time.Time, subject string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"exp": expiry.Unix(), "sub": subject})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte("{}")),
		base64.RawURLEncoding.EncodeToString(payload),
		"signature",
	}, ".")
}

// TestShutdownCutsLingeringRequestAtDeadline covers the deadline of the stop
// flow: a logs stream whose body has started being sent — the first line
// was received while the stream stayed open — is cut at the stop start
// (BeginStop), not waited for. The lingering downstream connection is
// closed at the deadline.
func TestShutdownCutsLingeringRequestAtDeadline(t *testing.T) {
	aborted := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A logs stream: the body starts being sent, then the stream
		// stays open until the stop cancels it.
		fmt.Fprint(w, "first line\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(aborted)
	}))
	defer upstream.Close()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeUsableSourceKubeconfig(t, sourcePath, upstream.URL)

	proxy := New(Targets{testTarget("dev",
		testResource("pods/log", "default", "get"),
		testResource("pods", "default", "get", "list", "watch"),
	)}, "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() { _ = proxy.Serve(listener) }()

	req, err := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/dev/api/v1/namespaces/default/pods/nginx/log", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer downstream-token")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	var resp *http.Response
	select {
	case err := <-errCh:
		t.Fatalf("Do() error = %v", err)
	case resp = <-respCh:
	}
	body := bufio.NewReader(resp.Body)
	if line, err := body.ReadString('\n'); err != nil || line != "first line\n" {
		t.Fatalf("the first line was not received from the open stream: %q, %v", line, err)
	}
	// Body sending has begun: the stream is open, the upstream handler
	// still runs. The stop start: the upstream request is cancelled
	// here — before anything waits on it.
	proxy.BeginStop()
	select {
	case <-aborted:
	case <-time.After(2 * time.Second):
		t.Fatal("the upstream request was not cancelled by the stop start")
	}

	// The stream does not linger past the stop: it ended here — the
	// aborted upstream gives the downstream a closed stream.
	ended := make(chan error, 1)
	go func() {
		_, err := body.ReadString('\n')
		ended <- err
	}()
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream lingered past the stop")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	proxy.Shutdown(ctx)
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("Shutdown waited %v; want it bounded by the deadline", waited)
	}
}

// TestRequestsAfterTheStopNeverReachUpstream covers the stop state: a
// request issued after the stop began (the upstream kubeconfig resolved,
// the final upstream call next) inherits the stop's cancellation — the
// upstream it would reach never learns about it.
func TestRequestsAfterTheStopNeverReachUpstream(t *testing.T) {
	hits := int32(0)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeUsableSourceKubeconfig(t, sourcePath, upstream.URL)

	proxy := New(testPolicy("dev"), "localhost")
	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	proxy.tokens = map[string]string{"downstream-token": "dev"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		_ = proxy.Serve(listener)
	}()

	// The stop begins before the request exists: whatever it issues from
	// here carries the stop.
	proxy.BeginStop()

	req, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/dev/api", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer downstream-token")
	req.URL.Scheme = "https"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() after the stop began: %v", err)
	}
	defer resp.Body.Close()
	if hits != 0 {
		t.Fatalf("a request issued after the stop began reached the upstream %d times", hits)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d; want %d (the request must fail before the upstream)", resp.StatusCode, http.StatusBadGateway)
	}
}
