package k8sproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"gopkg.in/yaml.v3"
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
		want bool
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
		want bool
	}{
		// dev: "*" covers every namespace and the all-namespaces list
		{"dev pods in default", "dev", http.MethodGet, "/api/v1/namespaces/default/pods/nginx", true},
		{"dev pods in other", "dev", http.MethodGet, "/api/v1/namespaces/other/pods/nginx", true},
		{"dev all-namespaces list", "dev", http.MethodGet, "/api/v1/pods", true},
		// dev: scope cluster covers the cluster-scoped collection; the
		// named GET carries the namespace of the path, which no
		// cluster-scoped rule covers
		{"dev list namespaces (cluster-scoped)", "dev", http.MethodGet, "/api/v1/namespaces", true},
		{"dev get one named namespace", "dev", http.MethodGet, "/api/v1/namespaces/foo", false},
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
		want bool
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
		name, method, path, query string
		wantVerb, wantResource, wantSubresource, wantNamespace, wantName string
		wantResourceRequest bool
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
		path, context string
		wantDecoded, wantRaw string
		wantWrong, wantOK bool
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

func TestSyncConfigWritesEmptyKubeconfigWithoutContexts(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev")

	cancel := runSyncConfig(t, New(testPolicy("dev"), "proxy.local"), dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "server: https://proxy.local:16443/dev")
	})

	writeSourceKubeconfig(t, sourcePath)
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "contexts: []")
	})
}

func TestSyncConfigReadsContextsFromUpstreamKubeconfig(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev")
	proxy := New(testPolicy("dev"), "proxy.local")
	cancel := runSyncConfig(t, proxy, dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "server: https://proxy.local:16443/dev")
	})

	// prod enters through a policy reload: the re-render the source
	// change triggers then carries it.
	proxy.SetTargets(testPolicy("dev", "prod"))
	writeSourceKubeconfig(t, sourcePath, "prod")
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
	cancel := runSyncConfig(t, New(testPolicy("prod", "dev"), "proxy.local"), dir)
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
	proxy := New(testPolicy("prod", "dev"), "proxy.local")
	cancel := runSyncConfig(t, proxy, dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "current-context: prod")
	})

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content = []byte(strings.Replace(string(content), "current-context: prod", "current-context: dev", 1))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// stage enters through a policy reload: the re-render the source
	// change triggers then carries it.
	proxy.SetTargets(testPolicy("prod", "dev", "stage"))
	writeSourceKubeconfig(t, sourcePath, "prod", "dev", "stage")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil &&
			strings.Contains(string(content), "server: https://proxy.local:16443/stage") &&
			strings.Contains(string(content), "current-context: dev")
	})
}

func TestSyncConfigUsesUpstreamNamespaceInitially(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfigWithNamespaces(t, sourcePath, map[string]string{"dev": "apps"}, "dev")
	cancel := runSyncConfig(t, New(testPolicy("dev"), "proxy.local"), dir)
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
	cancel := runSyncConfig(t, New(testPolicy("dev"), "proxy.local"), dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "namespace: apps")
	})

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content = []byte(strings.Replace(string(content), "namespace: apps", "namespace: local", 1))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	writeSourceKubeconfigWithNamespaces(t, sourcePath, map[string]string{"dev": "ops"}, "dev")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil &&
			strings.Contains(string(content), "namespace: local") &&
			!strings.Contains(string(content), "namespace: ops")
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
	cancel := runSyncConfig(t, New(testPolicy("dev"), "proxy.local"), "")
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
// without the explicit grant the same request is denied, and a token of
// another context on the URL is rejected before the upstream.
func TestServeProxiesKubectlLogs(t *testing.T) {
	seen := make(chan string, 4)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.Path + "?" + r.URL.RawQuery
		fmt.Fprint(w, "log line")
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

	// granted: kubectl logs and kubectl logs -f both reach the upstream
	for _, query := range []string{"", "?follow=true"} {
		if got := logsStatus("dev", "downstream-token", query); got != http.StatusOK {
			t.Fatalf("logs %q status = %d, want %d", query, got, http.StatusOK)
		}
		if got := <-seen; got != "/api/v1/namespaces/default/pods/nginx/log?"+strings.TrimPrefix(query, "?") {
			t.Fatalf("upstream request = %q, want the log path with %q", got, query)
		}
	}

	// denied by policy: without the explicit pods/log rule
	proxy.SetTargets(Targets{testTarget("dev", testResource("pods", "default", "get"))})
	if got := logsStatus("dev", "downstream-token", ""); got != http.StatusForbidden {
		t.Fatalf("logs status = %d, want %d (denied without pods/log)", got, http.StatusForbidden)
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
	// change the auth settings already resolved, the next session
	// resolves them anew.
	writeOIDCSourceKubeconfig(t, sourcePath, upstream.URL, newToken)
	requestKubeAPI(t, client, listener.Addr().String(), "dev", "downstream-token")
	if got := <-seen; got != "Bearer "+oldToken {
		t.Fatalf("second upstream Authorization = %q, want the token fixed for the session", got)
	}

	if err := proxy.resolveConnections(); err != nil {
		t.Fatal(err)
	}
	requestKubeAPI(t, client, listener.Addr().String(), "dev", "downstream-token")
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

// Regression: when writing the generated kubeconfig fails (e.g. a
// downstream process replaced the output directory with a symlink), the
// proxy's tokens must stay consistent with what is on disk and nothing may
// be written through the symlink.
func TestSyncConfigOnceKeepsTokensWhenWriteFails(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev")

	proxy := New(nil, "proxy.local")
	proxy.mu.Lock()
	proxy.tokens = map[string]string{"old-token": "dev"}
	proxy.mu.Unlock()

	dir := t.TempDir()
	real := t.TempDir()
	if err := os.Symlink(real, filepath.Join(dir, ".kube")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	if _, err := proxy.syncConfigOnce(testProxyPort, dir, ^uint32(0)); err == nil {
		t.Fatal("syncConfigOnce() through symlinked .kube should fail")
	}
	proxy.mu.RLock()
	_, ok := proxy.tokens["old-token"]
	proxy.mu.RUnlock()
	if !ok {
		t.Fatal("tokens were replaced despite write failure")
	}
	if _, err := os.Stat(filepath.Join(real, "config")); !os.IsNotExist(err) {
		t.Fatal("write escaped through symlinked .kube dir")
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

// Regression: existing contexts keep their tokens across syncs so clients
// reading the old kubeconfig are not rejected, while new contexts get fresh
// tokens. The prod context enters through a policy reload: the session's
// connections stay fixed, only the generated kubeconfig follows.
func TestSyncConfigReusesTokensForExistingContexts(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev")

	proxy := New(testPolicy("dev"), "proxy.local")
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
	devToken := contextToken(t, path, "dev")

	// The policy gains prod before the source does: the re-render the
	// source change triggers then carries both contexts.
	proxy.SetTargets(testPolicy("dev", "prod"))
	writeSourceKubeconfig(t, sourcePath, "dev", "prod")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "server: https://proxy.local:16443/prod")
	})
	if got := contextToken(t, path, "dev"); got != devToken {
		t.Fatalf("dev token was re-issued: %q, want %q", got, devToken)
	}
	if got := contextToken(t, path, "prod"); got == "" || got == devToken {
		t.Fatalf("prod token = %q, want a fresh token", got)
	}

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

func TestRenderKubeconfigIPv6Host(t *testing.T) {
	kubeconfig, _, err := New(nil, "::1").renderKubeconfig(testProxyPort, []kubeconfigContext{{Name: "dev"}}, "dev")
	if err != nil {
		t.Fatalf("renderKubeconfig() error = %v", err)
	}
	if !strings.Contains(string(kubeconfig), "server: https://[::1]:16443/dev") {
		t.Fatalf("kubeconfig does not bracket IPv6 host: %q", kubeconfig)
	}
}

func runSyncConfig(t *testing.T, proxy *Proxy, dir string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	ready := make(chan error, 1)
	go func() {
		errc <- proxy.SyncConfig(ctx, testProxyPort, dir, ready)
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
// flow: a watch the upstream never completes is cut at the deadline, not
// waited for. The stop start (BeginStop) is what cuts the upstream request
// itself; the lingering downstream connection is closed at the deadline.
func TestShutdownCutsLingeringRequestAtDeadline(t *testing.T) {
	aborted := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		go func() {
			// The upstream request the proxy opened carries the stop
			// context: BeginStop cancels it here.
			<-r.Context().Done()
			close(aborted)
		}()
		<-release // the watch never completes while this is held open
	}))
	defer upstream.Close()
	// Release the hanging handler before upstream.Close() waits on it.
	defer close(release)
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
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = proxy.Serve(listener) }()

	req, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/dev/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer downstream-token")
	req.URL.Scheme = "https"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	done := make(chan error, 1)
	go func() {
		_, err := client.Do(req)
		done <- err
	}()

	// Let the request reach the hanging upstream.
	time.Sleep(100 * time.Millisecond)
	// The stop start: the upstream request is cancelled here — before
	// anything waits on it.
	proxy.BeginStop()
	select {
	case <-aborted:
	case <-time.After(2 * time.Second):
		t.Fatal("the upstream request was not cancelled by the stop start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	proxy.Shutdown(ctx)
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("Shutdown waited %v; want it bounded by the deadline", waited)
	}

	// The request does not linger past the stop: it ended here — the
	// aborted upstream gives the downstream an error (upstream
	// unavailable) or a closed connection, whichever came first.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the request lingered past the stop")
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
