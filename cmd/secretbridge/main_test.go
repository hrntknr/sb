package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	proxyk8s "github.com/hrntknr/secretbridge/pkg/proxy/k8s"
	proxyssh "github.com/hrntknr/secretbridge/pkg/proxy/ssh"
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

func TestReadConfigMainOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, `
ssh:
  - host: github.com
  - host: "*.example.net"
    commands: [cat]
k8s:
  - cluster: dev
    mode: r
  - cluster: prod
    mode: rw
    namespace: default
`)

	cfg, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
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
	if cfg.K8s[0].Cluster != "dev" || cfg.K8s[0].Mode != proxyk8s.Read || !cfg.K8s[0].ClusterScope {
		t.Errorf("K8s[0] = %+v", cfg.K8s[0])
	}
	if cfg.K8s[1].Cluster != "prod" || cfg.K8s[1].Mode != proxyk8s.ReadWrite {
		t.Errorf("K8s[1] = %+v", cfg.K8s[1])
	}
}

func TestReadConfigMergesConfD(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
  - host: "*.hrntknr.net"
k8s:
  - cluster: dev
    mode: r
`)
	writeFile(t, filepath.Join(dir, "conf.d", "work.yaml"), `
ssh:
  - host: github.com
    commands: [cat]
  - host: internal.example
k8s:
  - cluster: dev
    mode: rw
  - cluster: prod
    mode: r
    namespace: default
`)

	cfg, err := readConfig(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
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
	if cfg.K8s[0].Cluster != "dev" || cfg.K8s[0].Mode != proxyk8s.ReadWrite {
		t.Errorf("K8s[0] = %+v, want dev rw", cfg.K8s[0])
	}
	if cfg.K8s[1].Cluster != "prod" || cfg.K8s[1].Mode != proxyk8s.Read {
		t.Errorf("K8s[1] = %+v, want prod r", cfg.K8s[1])
	}
}

func TestReadConfigConfDOrderedAlphabetically(t *testing.T) {
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

	cfg, err := readConfig(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
	}
	if len(cfg.SSH) != 1 {
		t.Fatalf("SSH len = %d, want 1", len(cfg.SSH))
	}
	if cfg.SSH[0].Commands[0] != "echo" {
		t.Errorf("expected last conf.d to win, got %+v", cfg.SSH[0].Commands)
	}
}

func TestReadConfigConfDMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
`)

	cfg, err := readConfig(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
	}
	if len(cfg.SSH) != 1 || cfg.SSH[0].Host != "github.com" {
		t.Fatalf("SSH = %+v", cfg.SSH)
	}
}

func TestReadConfigConfDIgnoresNonYAMLAndHidden(t *testing.T) {
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

	cfg, err := readConfig(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
	}
	if len(cfg.SSH) != 2 {
		t.Fatalf("SSH len = %d, want 2 (.yml should be included)", len(cfg.SSH))
	}
	if cfg.SSH[1].Host != "extra.example" {
		t.Errorf("SSH[1] = %+v, want extra.example", cfg.SSH[1])
	}
}

func TestReadConfigConfDInvalidYAMLErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
`)
	writeFile(t, filepath.Join(dir, "conf.d", "bad.yaml"), "ssh: [unclosed")

	_, err := readConfig(filepath.Join(dir, "config.yaml"))
	if err == nil {
		t.Fatal("readConfig() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "conf.d/bad.yaml") {
		t.Errorf("error should mention conf.d/bad.yaml, got %v", err)
	}
}

func TestReadConfigConfDInvalidTargetErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
ssh:
  - host: github.com
`)
	writeFile(t, filepath.Join(dir, "conf.d", "bad.yaml"), `
ssh:
  - commands: [cat]
`)

	_, err := readConfig(filepath.Join(dir, "config.yaml"))
	if err == nil {
		t.Fatal("readConfig() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "conf.d/bad.yaml") {
		t.Errorf("error should mention conf.d/bad.yaml, got %v", err)
	}
}

func TestReadConfigConfDAppendsNewTargets(t *testing.T) {
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

	cfg, err := readConfig(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
	}
	hosts := make([]string, 0, len(cfg.SSH))
	for _, t := range cfg.SSH {
		hosts = append(hosts, t.Host)
	}
	want := []string{"a.example", "b.example", "c.example"}
	if len(hosts) != len(want) {
		t.Fatalf("SSH hosts = %v, want %v", hosts, want)
	}
	for i, h := range want {
		if hosts[i] != h {
			t.Errorf("SSH[%d].Host = %q, want %q", i, hosts[i], h)
		}
	}
}

func TestFindSSHTarget(t *testing.T) {
	targets := proxyssh.Targets{{Host: "a"}, {Host: "b"}}
	if i := findSSHTarget(targets, "b"); i != 1 {
		t.Errorf("findSSHTarget(b) = %d, want 1", i)
	}
	if i := findSSHTarget(targets, "c"); i != -1 {
		t.Errorf("findSSHTarget(c) = %d, want -1", i)
	}
}

func TestFindK8sTarget(t *testing.T) {
	targets := proxyk8s.Targets{{Cluster: "a"}, {Cluster: "b"}}
	if i := findK8sTarget(targets, "b"); i != 1 {
		t.Errorf("findK8sTarget(b) = %d, want 1", i)
	}
	if i := findK8sTarget(targets, "c"); i != -1 {
		t.Errorf("findK8sTarget(c) = %d, want -1", i)
	}
}
