package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	proxyk8s "github.com/hrntknr/secretbridge/pkg/proxy/k8s"
	proxyssh "github.com/hrntknr/secretbridge/pkg/proxy/ssh"
)

var testPorts = Ports{SSH: 12222, K8s: 16443}

func TestProxyHostStringDefaultsToLocalhost(t *testing.T) {
	if got := (ProxyHost("")).String(); got != "localhost" {
		t.Fatalf("ProxyHost(\"\").String() = %q, want localhost", got)
	}
}

func TestSyncConfigWritesFilesUnderDir(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", sourcePath)
	writeSourceKubeconfig(t, sourcePath, "dev")
	s := &Bundle{
		SSH: proxyssh.New(nil),
		K8s: proxyk8s.New(nil),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- s.SyncConfig(ctx, "host.docker.internal", testPorts, dir)
	}()
	defer func() {
		cancel()
		if err := <-errc; err != nil {
			t.Fatalf("SyncConfig() error = %v", err)
		}
	}()

	for _, name := range []string{".ssh/config", ".ssh/id_ed25519", ".ssh/known_hosts", ".kube/config"} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(path); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Stat(%s) error = %v", name, err)
		}
	}
}

func TestSyncConfigWritesSSHOnlyAndReturns(t *testing.T) {
	dir := t.TempDir()
	s := &Bundle{
		SSH: proxyssh.New(nil),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- s.SyncConfig(ctx, "host.docker.internal", testPorts, dir)
	}()
	defer func() {
		cancel()
		if err := <-errc; err != nil {
			t.Fatalf("SyncConfig() error = %v", err)
		}
	}()

	for _, name := range []string{".ssh/config", ".ssh/id_ed25519", ".ssh/known_hosts"} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(path); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Stat(%s) error = %v", name, err)
		}
	}
}

func writeSourceKubeconfig(t *testing.T, path string, contexts ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\ncontexts:\n")
	for _, context := range contexts {
		b.WriteString("- name: ")
		b.WriteString(context)
		b.WriteString("\n  context: {}\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
