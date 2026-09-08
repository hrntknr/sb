package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrntknr/secretbridge/internal/k8sproxy"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func TestLoadMainOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, `
ssh:
  - host: github.com
  - host: "*.example.net"
    commands: [cat]
k8s:
  - context: dev
    mode: r
  - context: prod
    mode: rw
    namespace: default
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.SSH) != 2 {
		t.Fatalf("SSH len = %d, want 2", len(cfg.SSH))
	}
	if cfg.SSH[0].Host != "github.com" {
		t.Errorf("SSH[0] = %+v, want Host=github.com", cfg.SSH[0])
	}
	if !cfg.SSH[0].Shell || !cfg.SSH[0].Forward {
		t.Errorf("SSH[0] unrestricted should enable shell/forward, got %+v", cfg.SSH[0])
	}
	if cfg.SSH[1].Host != "*.example.net" || len(cfg.SSH[1].Commands) != 1 || cfg.SSH[1].Commands[0] != "cat" {
		t.Errorf("SSH[1] = %+v, want *.example.net with [cat]", cfg.SSH[1])
	}

	if len(cfg.K8s) != 2 {
		t.Fatalf("K8s len = %d, want 2", len(cfg.K8s))
	}
	if cfg.K8s[0].Context != "dev" || cfg.K8s[0].Mode != k8sproxy.Read || !cfg.K8s[0].ClusterScope {
		t.Errorf("K8s[0] = %+v", cfg.K8s[0])
	}
	if cfg.K8s[1].Context != "prod" || cfg.K8s[1].Mode != k8sproxy.ReadWrite {
		t.Errorf("K8s[1] = %+v", cfg.K8s[1])
	}
}

func TestLoadMergesConfD(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
  - host: "*.hrntknr.net"
k8s:
  - context: dev
    mode: r
`)
	writeFile(t, filepath.Join(dir, "conf.d", "work.yaml"), `
ssh:
  - host: github.com
    commands: [cat]
  - host: internal.example
k8s:
  - context: dev
    mode: rw
  - context: prod
    mode: r
    namespace: default
`)

	cfg, err := Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.SSH) != 3 {
		t.Fatalf("SSH len = %d, want 3", len(cfg.SSH))
	}
	if cfg.SSH[0].Host != "github.com" {
		t.Errorf("SSH[0].Host = %q, want github.com", cfg.SSH[0].Host)
	}
	if len(cfg.SSH[0].Commands) != 1 || cfg.SSH[0].Commands[0] != "cat" {
		t.Errorf("SSH[0] = %+v, want overridden with [cat]", cfg.SSH[0])
	}
	if cfg.SSH[0].Shell || cfg.SSH[0].Forward {
		t.Errorf("SSH[0] shell/forward should be false after override, got %+v", cfg.SSH[0])
	}
	if cfg.SSH[1].Host != "*.hrntknr.net" {
		t.Errorf("SSH[1].Host = %q, want *.hrntknr.net", cfg.SSH[1].Host)
	}
	if cfg.SSH[2].Host != "internal.example" {
		t.Errorf("SSH[2].Host = %q, want internal.example", cfg.SSH[2].Host)
	}

	if len(cfg.K8s) != 2 {
		t.Fatalf("K8s len = %d, want 2", len(cfg.K8s))
	}
	if cfg.K8s[0].Context != "dev" || cfg.K8s[0].Mode != k8sproxy.ReadWrite {
		t.Errorf("K8s[0] = %+v, want dev rw", cfg.K8s[0])
	}
	if cfg.K8s[1].Context != "prod" || cfg.K8s[1].Mode != k8sproxy.Read {
		t.Errorf("K8s[1] = %+v, want prod r", cfg.K8s[1])
	}
}

func TestLoadConfDOrderedAlphabetically(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
    commands: [cat]
`)
	writeFile(t, filepath.Join(dir, "conf.d", "a.yaml"), `
ssh:
  - host: github.com
    commands: [ls]
`)
	writeFile(t, filepath.Join(dir, "conf.d", "b.yaml"), `
ssh:
  - host: github.com
    commands: [echo]
`)

	cfg, err := Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.SSH) != 1 {
		t.Fatalf("SSH len = %d, want 1", len(cfg.SSH))
	}
	if cfg.SSH[0].Commands[0] != "echo" {
		t.Errorf("expected last conf.d to win, got %+v", cfg.SSH[0].Commands)
	}
}

func TestLoadConfDMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
`)

	cfg, err := Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.SSH) != 1 || cfg.SSH[0].Host != "github.com" {
		t.Fatalf("SSH = %+v", cfg.SSH)
	}
}

func TestLoadConfDIgnoresNonYAMLAndHidden(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
`)
	writeFile(t, filepath.Join(dir, "conf.d", "README.md"), "ignored")
	writeFile(t, filepath.Join(dir, "conf.d", ".gitkeep"), "")
	writeFile(t, filepath.Join(dir, "conf.d", "backup.yaml.bak"), "ignored")
	if err := os.MkdirAll(filepath.Join(dir, "conf.d", "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "conf.d", "extra.yml"), `
ssh:
  - host: extra.example
`)

	cfg, err := Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.SSH) != 2 {
		t.Fatalf("SSH len = %d, want 2 (.yml should be included)", len(cfg.SSH))
	}
	if cfg.SSH[1].Host != "extra.example" {
		t.Errorf("SSH[1] = %+v, want extra.example", cfg.SSH[1])
	}
}

func TestLoadConfDInvalidYAMLErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
`)
	writeFile(t, filepath.Join(dir, "conf.d", "bad.yaml"), "ssh: [unclosed")

	_, err := Load(filepath.Join(dir, "config.yaml"))
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "conf.d/bad.yaml") {
		t.Errorf("error should mention conf.d/bad.yaml, got %v", err)
	}
}

func TestLoadConfDInvalidTargetErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
`)
	writeFile(t, filepath.Join(dir, "conf.d", "bad.yaml"), `
ssh:
  - commands: [cat]
`)

	_, err := Load(filepath.Join(dir, "config.yaml"))
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "conf.d/bad.yaml") {
		t.Errorf("error should mention conf.d/bad.yaml, got %v", err)
	}
}

func TestLoadConfDAppendsNewTargets(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: a.example
`)
	writeFile(t, filepath.Join(dir, "conf.d", "first.yaml"), `
ssh:
  - host: b.example
`)
	writeFile(t, filepath.Join(dir, "conf.d", "second.yaml"), `
ssh:
  - host: c.example
`)

	cfg, err := Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	hosts := make([]string, 0, len(cfg.SSH))
	for _, target := range cfg.SSH {
		hosts = append(hosts, target.Host)
	}
	want := []string{"a.example", "b.example", "c.example"}
	if len(hosts) != len(want) {
		t.Fatalf("SSH hosts = %v, want %v", hosts, want)
	}
	for i, host := range want {
		if hosts[i] != host {
			t.Errorf("SSH[%d].Host = %q, want %q", i, hosts[i], host)
		}
	}
}

func TestLoadInvalidModeErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, `
k8s:
  - context: dev
    mode: admin
`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), `invalid mode "admin"`) {
		t.Fatalf("Load() error = %v, want invalid mode error", err)
	}
}

// startWatch writes an initial config, starts Watch on it, and returns the
// config path and a channel of the configs Watch delivers.
func startWatch(t *testing.T) (string, <-chan Config) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, `
ssh:
  - host: initial.example
`)
	configs := make(chan Config, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Watch(ctx, path, func(cfg Config) { configs <- cfg })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Watch did not stop after cancel")
		}
	})
	return path, configs
}

func waitForInitial(t *testing.T, configs <-chan Config) {
	t.Helper()
	select {
	case <-configs:
	case <-time.After(5 * time.Second):
		t.Fatal("initial onChange not called")
	}
}

// drainHosts reads one config from the channel if available and lists its
// ssh host targets.
func drainHosts(configs <-chan Config) []string {
	select {
	case cfg := <-configs:
		hosts := make([]string, 0, len(cfg.SSH))
		for _, target := range cfg.SSH {
			hosts = append(hosts, target.Host)
		}
		return hosts
	default:
		return nil
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func waitForHosts(t *testing.T, configs <-chan Config, want []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := drainHosts(configs); equalStrings(got, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ssh hosts = %v, want %v", drainHosts(configs), want)
}

func TestWatchCallsOnChangeInitially(t *testing.T) {
	_, configs := startWatch(t)
	waitForInitial(t, configs)
}

func TestWatchReloadsOnConfigChange(t *testing.T) {
	path, configs := startWatch(t)
	waitForInitial(t, configs)

	writeFile(t, path, `
ssh:
  - host: updated.example
`)
	waitForHosts(t, configs, []string{"updated.example"})
}

func TestWatchReloadsOnConfDChange(t *testing.T) {
	path, configs := startWatch(t)
	waitForInitial(t, configs)

	writeFile(t, filepath.Join(filepath.Dir(path), "conf.d", "10-extra.yaml"), `
ssh:
  - host: extra.example
`)
	waitForHosts(t, configs, []string{"initial.example", "extra.example"})
}

func TestWatchKeepsWatchingAfterInvalidChange(t *testing.T) {
	path, configs := startWatch(t)
	waitForInitial(t, configs)

	writeFile(t, path, "ssh: [unclosed")
	writeFile(t, path, `
ssh:
  - host: recovered.example
`)
	waitForHosts(t, configs, []string{"recovered.example"})
}
