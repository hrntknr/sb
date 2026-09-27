package k8sproxy_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hrntknr/sb/internal/config/v3"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"gopkg.in/yaml.v3"
)

// upstreamRecord is one request the recording upstream saw: the method,
// the path, and the body — exactly what the proxy forwarded.
type upstreamRecord struct {
	method string
	path   string
	body   string
}

type upstreamLog struct {
	mu   sync.Mutex
	seen []upstreamRecord
}

func (l *upstreamLog) add(rec upstreamRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, rec)
}

// entries returns the recorded requests under the lock, in order.
func (l *upstreamLog) entries() []upstreamRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]upstreamRecord{}, l.seen...)
}

// recordingUpstream starts a TLS test server that records every request
// it sees and answers No Content. The record is taken before the
// response is written, so a request that reached the upstream is
// recorded by the time the downstream client sees its response.
func recordingUpstream(t *testing.T) (*httptest.Server, *upstreamLog) {
	t.Helper()
	log := &upstreamLog{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		log.add(upstreamRecord{method: r.Method, path: r.URL.Path, body: string(body)})
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server, log
}

// TestConfigConnectsTheFormsToTheUpstream loads a config with all three
// k8s forms — the mode shorthand (dev), the context verbs with resources
// omitted (ops), and the enumerated resources with the namespace and
// verbs omitted (prod) — and runs the loaded targets through the TLS
// proxy to a recording upstream: the connection the config defines is
// the one the proxy enforces.
//
// A request the form grants reaches the upstream with the method and
// the body the client sent; a request the form does not cover — a verb
// no rule carries (deletecollection on a collection, a create on a
// read-only form), or a write on a subresource no rule names (pods/log,
// which no mode covers) — is rejected before the upstream, and the
// upstream log stays without it.
func TestConfigConnectsTheFormsToTheUpstream(t *testing.T) {
	upstream, log := recordingUpstream(t)

	// The source kubeconfig the proxy resolves its upstream connections
	// from: one cluster pointing at the recording upstream, one user
	// per context, every context on the cluster.
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeConnectSourceKubeconfig(t, sourcePath, upstream.URL)

	// The config, loaded as the loader reads it: the forms decide what
	// the targets grant, and the proxy enforces the same connection.
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	writeConnectConfig(t, configPath, `version: 3
k8s:
  - context: dev
    mode: rw
  - context: ops
    verbs: [get, list, watch]
  - context: prod
    resources:
      - group: ""
        resource: pods
`)
	cfg, err := v3.Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// The proxy serves the listener; the issuance resolves the upstream
	// connections from the source kubeconfig and writes the generated
	// kubeconfig — with the downstream tokens — into dir.
	dir := t.TempDir()
	proxy := k8sproxy.New(cfg.K8sTargets(), "localhost")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = proxy.Serve(listener)
	}()
	serveAndIssue(t, proxy, listener, dir)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	proxyURL := "https://" + listener.Addr().String()
	tokens := issuedTokens(t, dir)

	requests := []struct {
		context, method, path, body string
		granted                     bool
	}{
		// dev: the mode shorthand. Every verb is granted on every
		// regular resource — POST is a create, PUT an update, PATCH a
		// patch, DELETE on one pod a delete — and each reaches the
		// upstream with the method and the body the client sent.
		{context: "dev", method: http.MethodPost, path: "/api/v1/namespaces/default/pods", body: `{"kind":"Pod","apiVersion":"v1","metadata":{"name":"nginx"}}`, granted: true},
		{context: "dev", method: http.MethodPut, path: "/api/v1/namespaces/default/pods/nginx", body: `{"kind":"Pod","apiVersion":"v1","metadata":{"name":"nginx"}}`, granted: true},
		{context: "dev", method: http.MethodPatch, path: "/api/v1/namespaces/default/pods/nginx", body: `{"spec":{"containers":[]}}`, granted: true},
		{context: "dev", method: http.MethodDelete, path: "/api/v1/namespaces/default/pods/nginx", body: "", granted: true},
		// a delete on the collection is deletecollection — a verb no
		// supported list carries — and stays rejected.
		{context: "dev", method: http.MethodDelete, path: "/api/v1/namespaces/default/pods", body: "", granted: false},
		// a write on pods/log is a write on a subresource no rule names:
		// no mode covers it, so it stays rejected.
		{context: "dev", method: http.MethodPost, path: "/api/v1/namespaces/default/pods/nginx/log", body: `{"tailLines":1}`, granted: false},
		// ops: the context verbs with resources omitted. Reads are
		// granted on every resource; a create is not among the verbs.
		{context: "ops", method: http.MethodGet, path: "/api/v1/namespaces/default/pods", body: "", granted: true},
		{context: "ops", method: http.MethodPost, path: "/api/v1/namespaces/default/pods", body: `{"kind":"Pod","apiVersion":"v1"}`, granted: false},
		// prod: the enumerated resources, the namespace and the verbs
		// omitted. The grant is every verb on pods in every namespace —
		// "other" is one of them — and nothing on pods/log.
		{context: "prod", method: http.MethodPost, path: "/api/v1/namespaces/other/pods", body: `{"kind":"Pod","apiVersion":"v1"}`, granted: true},
		{context: "prod", method: http.MethodGet, path: "/api/v1/namespaces/default/pods/nginx/log", body: "", granted: false},
	}
	want := make([]upstreamRecord, 0, len(requests))
	for _, tt := range requests {
		t.Run(tt.context+" "+tt.method+" "+tt.path, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, proxyURL+"/"+tt.context+tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("NewRequest() error = %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+tokens[tt.context])
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Do() error = %v", err)
			}
			resp.Body.Close()
			if tt.granted && resp.StatusCode != http.StatusNoContent {
				t.Fatalf("granted request status = %d, want %d", resp.StatusCode, http.StatusNoContent)
			}
			if !tt.granted && resp.StatusCode != http.StatusForbidden {
				t.Fatalf("rejected request status = %d, want %d", resp.StatusCode, http.StatusForbidden)
			}
			if tt.granted {
				want = append(want, upstreamRecord{method: tt.method, path: tt.path, body: tt.body})
			}
		})
	}

	// What the upstream saw is what the forms granted: every granted
	// request once, in order, and nothing else.
	got := log.entries()
	if len(got) != len(want) {
		t.Fatalf("the upstream saw %d requests, want %d (every granted one, nothing else)", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("the upstream saw %d: %s %s %q, want %s %s %q", i, got[i].method, got[i].path, got[i].body, w.method, w.path, w.body)
		}
	}
}

// serveAndIssue runs the proxy's issuance: SyncConfig resolves the
// upstream connections from the source kubeconfig and writes the
// generated kubeconfig with the downstream tokens, and holds the session
// until the test's cleanup cancels it.
func serveAndIssue(t *testing.T, proxy *k8sproxy.Proxy, listener net.Listener, dir string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan error, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- proxy.SyncConfig(ctx, listener.Addr().(*net.TCPAddr).Port, dir, ready)
	}()
	if err := <-ready; err != nil {
		t.Fatalf("SyncConfig() issuance: %v", err)
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
}

// writeConnectSourceKubeconfig writes the source kubeconfig the proxy
// resolves upstream connections from: one cluster pointing at server,
// one user per context, and every context on the cluster.
func writeConnectSourceKubeconfig(t *testing.T, path, server string) {
	t.Helper()
	content := "apiVersion: v1\nkind: Config\nclusters:\n" +
		"- name: upstream\n  cluster:\n    server: " + server + "\n    insecure-skip-tls-verify: true\n" +
		"users:\n" +
		"- name: dev\n  user:\n    token: upstream-token\n" +
		"- name: ops\n  user:\n    token: upstream-token\n" +
		"- name: prod\n  user:\n    token: upstream-token\n" +
		"contexts:\n" +
		"- name: dev\n  context:\n    cluster: upstream\n    user: dev\n" +
		"- name: ops\n  context:\n    cluster: upstream\n    user: ops\n" +
		"- name: prod\n  context:\n    cluster: upstream\n    user: prod\n" +
		"current-context: dev\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

// writeConnectConfig writes the config at path.
func writeConnectConfig(t *testing.T, path, config string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

// issuedUser is the user entry of the generated kubeconfig: the token
// it carries, named by the context it was issued for.
type issuedUser struct {
	Name string `yaml:"name"`
	User struct {
		Token string `yaml:"token"`
	} `yaml:"user"`
}

// issuedConfig is the shape of the generated kubeconfig as far as the
// tokens go: one user per issued context.
type issuedConfig struct {
	Users []issuedUser `yaml:"users"`
}

// issuedTokens reads the downstream tokens out of the generated kubeconfig
// the issuance wrote into dir: the map from the context's name to its
// token, the same one the proxy authorizes the downstream request by.
func issuedTokens(t *testing.T, dir string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, ".kube", "config"))
	if err != nil {
		t.Fatalf("read generated kubeconfig: %v", err)
	}
	var config issuedConfig
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatalf("unmarshal generated kubeconfig: %v", err)
	}
	tokens := make(map[string]string, len(config.Users))
	for _, user := range config.Users {
		tokens[user.Name] = user.User.Token
	}
	if len(tokens) != 3 {
		t.Fatalf("the generated kubeconfig carries %d tokens, want 3 (one per context)", len(tokens))
	}
	return tokens
}
