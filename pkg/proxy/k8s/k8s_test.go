package k8s

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testProxyPort = 16443

func TestTargetsAllowReadWriteToIncludeRead(t *testing.T) {
	targets := Targets{
		{Mode: ReadWrite, Cluster: "pear", ClusterScope: true},
		{Mode: Read, Cluster: "*", ClusterScope: true},
	}

	tests := []struct {
		verb      Verb
		cluster   string
		namespace string
		want      bool
	}{
		{Read, "pear", "default", true},
		{ReadWrite, "pear", "default", true},
		{Read, "test", "default", true},
		{ReadWrite, "test", "default", false},
		{Read, "pear", "", true},
		{ReadWrite, "test", "", false},
	}

	for _, tt := range tests {
		if got := targets.Allows(tt.verb, tt.cluster, tt.namespace); got != tt.want {
			t.Fatalf("Allows(%q, %q, %q) = %v, want %v", tt.verb, tt.cluster, tt.namespace, got, tt.want)
		}
	}
}

func TestEmptyTargetsDenyAll(t *testing.T) {
	var targets Targets
	for _, tt := range []struct {
		verb      Verb
		namespace string
	}{
		{Read, ""},
		{Read, "default"},
		{ReadWrite, "default"},
	} {
		if targets.Allows(tt.verb, "pear", tt.namespace) {
			t.Fatalf("empty targets allowed (%q, %q)", tt.verb, tt.namespace)
		}
	}
}

func TestTargetsAllowContextIsCaseSensitive(t *testing.T) {
	targets := Targets{{Mode: ReadWrite, Cluster: "pear", ClusterScope: true}}

	if got := targets.Allows(Read, "Pear", "default"); got {
		t.Fatalf("Allows(%q, %q) = %v, want false", Read, "Pear", got)
	}
}

func TestTargetsAllowsNamespaceRestriction(t *testing.T) {
	targets := Targets{
		{Mode: ReadWrite, Cluster: "prod", Namespaces: []string{"team-*"}},
		{Mode: Read, Cluster: "*", ClusterScope: true},
	}

	tests := []struct {
		name      string
		verb      Verb
		cluster   string
		namespace string
		want      bool
	}{
		{"rw in allowed namespace", ReadWrite, "prod", "team-alpha", true},
		{"rw in other namespace denied", ReadWrite, "prod", "other", false},
		{"read in other namespace allowed by wildcard", Read, "prod", "other", true},
		{"cluster-scoped rw denied", ReadWrite, "prod", "", false},
		{"cluster-scoped read allowed by wildcard", Read, "prod", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := targets.Allows(tt.verb, tt.cluster, tt.namespace); got != tt.want {
				t.Fatalf("Allows(%q, %q, %q) = %v, want %v", tt.verb, tt.cluster, tt.namespace, got, tt.want)
			}
		})
	}
}

func TestRequestVerbClassifiesKubernetesActions(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   Verb
	}{
		{
			name:   "list pods",
			method: http.MethodGet,
			path:   "/api/v1/namespaces/default/pods",
			want:   Read,
		},
		{
			name:   "watch pods",
			method: http.MethodGet,
			path:   "/api/v1/namespaces/default/pods",
			want:   Read,
		},
		{
			name:   "get pod logs",
			method: http.MethodGet,
			path:   "/api/v1/namespaces/default/pods/nginx/log",
			want:   Read,
		},
		{
			name:   "create pod",
			method: http.MethodPost,
			path:   "/api/v1/namespaces/default/pods",
			want:   ReadWrite,
		},
		{
			name:   "get pod exec",
			method: http.MethodGet,
			path:   "/api/v1/namespaces/default/pods/nginx/exec",
			want:   ReadWrite,
		},
		{
			name:   "post pod exec",
			method: http.MethodPost,
			path:   "/api/v1/namespaces/default/pods/nginx/exec",
			want:   ReadWrite,
		},
		{
			name:   "get pod attach",
			method: http.MethodGet,
			path:   "/api/v1/namespaces/default/pods/nginx/attach",
			want:   ReadWrite,
		},
		{
			name:   "get pod portforward",
			method: http.MethodGet,
			path:   "/api/v1/namespaces/default/pods/nginx/portforward",
			want:   ReadWrite,
		},
		{
			name:   "get pod proxy path",
			method: http.MethodGet,
			path:   "/api/v1/namespaces/default/pods/nginx/proxy/api",
			want:   ReadWrite,
		},
		{
			name:   "get service proxy",
			method: http.MethodGet,
			path:   "/api/v1/namespaces/default/services/web/proxy",
			want:   ReadWrite,
		},
		{
			name:   "get node proxy",
			method: http.MethodGet,
			path:   "/api/v1/nodes/node-1/proxy/stats",
			want:   ReadWrite,
		},
		{
			name:   "get custom resource status",
			method: http.MethodGet,
			path:   "/apis/example.com/v1/namespaces/default/widgets/widget-1/status",
			want:   Read,
		},
		{
			name:   "patch custom resource status",
			method: http.MethodPatch,
			path:   "/apis/example.com/v1/namespaces/default/widgets/widget-1/status",
			want:   ReadWrite,
		},
		{
			name:   "create self subject access review",
			method: http.MethodPost,
			path:   "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
			want:   Read,
		},
		{
			name:   "create subject access review",
			method: http.MethodPost,
			path:   "/apis/authorization.k8s.io/v1/subjectaccessreviews",
			want:   ReadWrite,
		},
		{
			name:   "create local subject access review",
			method: http.MethodPost,
			path:   "/apis/authorization.k8s.io/v1/namespaces/default/localsubjectaccessreviews",
			want:   ReadWrite,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := classifyRequest(tt.method, tt.path); got != tt.want {
				t.Fatalf("classifyRequest(%q, %q) verb = %q, want %q", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestClassifyRequestNamespace(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   string
	}{
		{"namespaced", http.MethodGet, "/api/v1/namespaces/default/pods", "default"},
		{"namespaced resource", http.MethodPost, "/api/v1/namespaces/apps/pods", "apps"},
		{"cluster-scoped", http.MethodGet, "/api/v1/nodes", ""},
		{"all namespaces", http.MethodGet, "/api/v1/pods", ""},
		{"non-resource", http.MethodGet, "/healthz", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := classifyRequest(tt.method, tt.path); got != tt.want {
				t.Fatalf("classifyRequest(%q, %q) namespace = %q, want %q", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestUpstreamRequestPath(t *testing.T) {
	tests := []struct {
		path string
		want string
		ok   bool
	}{
		{"/dev/api/v1/namespaces/default/pods", "/api/v1/namespaces/default/pods", true},
		{"/dev/api", "/api", true},
		{"/dev/apis", "/apis", true},
		{"/team%2Fdev/api/v1/namespaces/default/pods/nginx/exec", "/api/v1/namespaces/default/pods/nginx/exec", true},
		{"/dev", "", false},
		{"/dev/foo", "/foo", true},
		{"/", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := upstreamRequestPath(tt.path)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("upstreamRequestPath(%q) = %q, %v; want %q, %v", tt.path, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestRenderKubeconfig(t *testing.T) {
	kubeconfig, _, err := renderKubeconfig("proxy.local", testProxyPort, []kubeconfigContext{{Name: "pear"}, {Name: "test"}}, "test")
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}

	text := string(kubeconfig)
	if !strings.Contains(text, "server: https://proxy.local:16443/pear") {
		t.Fatalf("kubeconfig does not contain pear proxy path: %q", text)
	}
	if !strings.Contains(text, "server: https://proxy.local:16443/test") {
		t.Fatalf("kubeconfig does not contain test proxy path: %q", text)
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
	kubeconfig, _, err := renderKubeconfig("proxy.local", testProxyPort, []kubeconfigContext{{Name: "team/dev"}}, "team/dev")
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}

	text := string(kubeconfig)
	if !strings.Contains(text, "server: https://proxy.local:16443/team%2Fdev") {
		t.Fatalf("kubeconfig does not contain escaped proxy path: %q", text)
	}
}

func TestRenderKubeconfigIncludesNamespace(t *testing.T) {
	kubeconfig, _, err := renderKubeconfig("proxy.local", testProxyPort, []kubeconfigContext{
		{Name: "dev", Namespace: "apps"},
	}, "dev")
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}

	text := string(kubeconfig)
	if !strings.Contains(text, "namespace: apps") {
		t.Fatalf("kubeconfig = %q", text)
	}
}

func TestRenderKubeconfigWithoutContexts(t *testing.T) {
	kubeconfig, _, err := renderKubeconfig("proxy.local", testProxyPort, nil, "")
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}
	text := string(kubeconfig)
	for _, want := range []string{"clusters: []", "users: []", "contexts: []"} {
		if !strings.Contains(text, want) {
			t.Fatalf("issue() kubeconfig = %q, want %q", text, want)
		}
	}
}

func TestSyncConfigWritesEmptyKubeconfigWithoutContexts(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev")

	cancel := runSyncConfig(t, New(nil), "proxy.local", dir)
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
	cancel := runSyncConfig(t, New(nil), "proxy.local", dir)
	defer cancel()

	path := filepath.Join(dir, ".kube", "config")
	waitFor(t, func() bool {
		content, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(content), "server: https://proxy.local:16443/dev")
	})

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
	cancel := runSyncConfig(t, New(nil), "proxy.local", dir)
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
	cancel := runSyncConfig(t, New(nil), "proxy.local", dir)
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
	cancel := runSyncConfig(t, New(nil), "proxy.local", dir)
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
	cancel := runSyncConfig(t, New(nil), "proxy.local", dir)
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
	cancel := runSyncConfig(t, New(nil), "proxy.local", "")
	defer cancel()

	waitFor(t, func() bool {
		_, err := os.Stat(filepath.Join(dir, ".kube", "config"))
		return err == nil
	})
}

func TestServeRequiresListener(t *testing.T) {
	if err := New(nil).Serve(nil); err == nil {
		t.Fatalf("Serve() error = nil, want error")
	}
}

func TestServeRejectsPathWithoutUpstreamAPIPath(t *testing.T) {
	proxy := New(Targets{{Mode: ReadWrite, Cluster: "dev", ClusterScope: true}})
	proxy.tokens = map[string]string{"downstream-token": "dev"}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.local/dev", nil)
	req.Header.Set("Authorization", "Bearer downstream-token")
	rec := httptest.NewRecorder()

	proxy.serveHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestServeProxiesToUpstreamContext(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api" {
			t.Fatalf("upstream path = %q, want /api", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer upstream-token" {
			t.Fatalf("upstream Authorization = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeUsableSourceKubeconfig(t, sourcePath, upstream.URL)

	proxy := New(Targets{{Mode: Read, Cluster: "dev", ClusterScope: true}})
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

func TestServeProxiesWithOIDCAuthProvider(t *testing.T) {
	idToken := testIDToken(t, time.Now().Add(time.Hour))
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+idToken {
			t.Fatalf("upstream Authorization = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeOIDCSourceKubeconfig(t, sourcePath, upstream.URL, idToken)

	proxy := New(Targets{{Mode: Read, Cluster: "dev", ClusterScope: true}})
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

	proxy := New(Targets{{Mode: Read, Cluster: "*", ClusterScope: true}})
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
				t.Fatalf("refresh_token = %q, want old-refresh", got)
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

	proxy := New(Targets{{Mode: Read, Cluster: "dev", ClusterScope: true}})
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

	proxy := New(Targets{{Mode: Read, Cluster: "dev", ClusterScope: true}})
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

	writeOIDCSourceKubeconfig(t, sourcePath, upstream.URL, newToken)
	requestKubeAPI(t, client, listener.Addr().String(), "dev", "downstream-token")
	if got := <-seen; got != "Bearer "+newToken {
		t.Fatalf("second upstream Authorization = %q, want new token", got)
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

func runSyncConfig(t *testing.T, proxy *Proxy, host, dir string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- proxy.SyncConfig(ctx, host, testProxyPort, dir)
	}()
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
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\ncontexts:\n")
	for _, context := range contexts {
		b.WriteString("- name: ")
		b.WriteString(context)
		if namespace := namespaces[context]; namespace != "" {
			b.WriteString("\n  context:\n    namespace: ")
			b.WriteString(namespace)
			b.WriteString("\n")
		} else {
			b.WriteString("\n  context: {}\n")
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
