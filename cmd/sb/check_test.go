package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrntknr/sb/internal/awsproxy"
	"github.com/hrntknr/sb/internal/config/v3"
)

func TestRenderConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, "config.yaml")
	writeConfig(t, path, `version: 3
container:
  runtime: docker
  image: ghcr.io/hrntknr/sh:full
  mounts:
    - source: ~/work
      target: /work
      readOnly: true
  environment:
    LANG: {inherit: true}
ssh:
  - host: github.com
    user: git
    port: 22
    access: full
  - host: "*.example.net"
    access: full
k8s:
  - context: dev
    resources:
      - group: ""
        resource: pods
        namespace: default
        verbs: [get, list, watch]
      - group: ""
        resource: namespaces
        scope: cluster
        verbs: [get]
  - context: ops
    mode: rw
aws:
  - profile: dev
    roleArn: arn:aws:iam::123456789012:role/sb-dev
    regions: [eu-west-1]
    services:
      - name: dynamodb
        mode: ro
      - name: sts
        mode: rw
`)
	cfg, err := v3.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	out := renderConfig(cfg)
	for _, want := range []string{
		"Static checks only: no credentials are read and no cluster is contacted.\n",
		"ssh:\n  - host: github.com\n    user: git\n    port: 22\n    access: full (shell, any exec, subsystem, TCP forwarding)\n",
		"  - host: *.example.net\n    access: full",
		"k8s:\n  - context: dev\n",
		"    - core pods in default: get, list, watch\n",
		"    - core namespaces (cluster-scoped): get\n",
		"  - context: ops\n",
		"    mode: rw (get, list, watch, create, update, patch, delete on every resource of the stable API — every namespace and the cluster's root alike; no subresource is included)\n",
		// the actual permission set K8sTargets generates — the same
		// grant the proxy will enforce, one resource at a time
		"    - core bindings in * (all namespaces): get, list, watch, create, update, patch, delete\n",
		"    - core componentstatuses (cluster-scoped): get, list, watch, create, update, patch, delete\n",
		"    - apps deployments in * (all namespaces): get, list, watch, create, update, patch, delete\n",
		"aws:\n  - profile: dev\n    roleArn: arn:aws:iam::123456789012:role/sb-dev\n    regions: eu-west-1\n",
		"    dynamodb: ro\n    sts: rw\n",
		"container:\n  runtime: docker\n  image: ghcr.io/hrntknr/sh:full\n",
		"  mounts:\n    - " + filepath.Join(dir, "work") + " -> /work (read-only)\n",
		"  environment:\n    LANG: inherit\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("renderConfig() missing %q:\n%s", want, out)
		}
	}
}

func TestRenderConfigEmpty(t *testing.T) {
	if got, want := renderConfig(v3.Config{}), "Static checks only: no credentials are read and no cluster is contacted.\n"; got != want {
		t.Errorf("renderConfig() = %q, want %q", got, want)
	}
}

func TestRenderConfigRoleOmitted(t *testing.T) {
	out := renderConfig(v3.Config{
		AWS: []v3.AWSRule{{Profile: "dev", Services: []awsproxy.Service{{Name: "dynamodb", Mode: "ro"}}}},
	})
	for _, want := range []string{"roleArn: (omitted: signs with the source profile's own credentials)\n", "regions: (any)\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderConfig() missing %q:\n%s", want, out)
		}
	}

}

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
