package v3

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hrntknr/sb/internal/awsproxy"
)

// designExample is the config example from V3_DESIGN.md.
const designExample = `version: 3
container:
  runtime: docker
  image: ghcr.io/hrntknr/sh:full
  mounts:
    - source: ~/work
      target: /work
      readOnly: false
  environment:
    LANG: {inherit: true}
    FOO: {value: bar}
ssh:
  - host: github.com
    user: git                   # optional: restrict the upstream user
    port: 22
    access: full
k8s:
  - context: dev
    resources:
      - group: ""                 # core API group
        resource: pods
        namespace: default
        verbs: [get, list, watch]
      - group: ""
        resource: pods/log
        namespace: default
        verbs: [get]             # kubectl logs (including -f)
aws:
  - profile: dev
    # roleArn: arn:aws:iam::123456789012:role/sb-dev
    regions: [eu-west-1]
    services:
      - name: dynamodb
        mode: ro
`

func TestLoadDesignExample(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, designExample)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.SSH) != 1 {
		t.Fatalf("SSH len = %d, want 1", len(cfg.SSH))
	}
	if cfg.SSH[0] != (SSHRule{Host: "github.com", User: "git", Port: 22, Access: "full"}) {
		t.Errorf("SSH[0] = %+v", cfg.SSH[0])
	}
	if len(cfg.K8s) != 1 || cfg.K8s[0].Context != "dev" {
		t.Fatalf("K8s = %+v", cfg.K8s)
	}
	wantResources := []ResourceRule{
		{Group: "", Resource: "pods", Namespace: "default", Verbs: []string{"get", "list", "watch"}},
		{Group: "", Resource: "pods/log", Namespace: "default", Verbs: []string{"get"}},
	}
	if !reflect.DeepEqual(cfg.K8s[0].Resources, wantResources) {
		t.Errorf("K8s[0].Resources = %+v, want %+v", cfg.K8s[0].Resources, wantResources)
	}
	wantAWS := []AWSRule{{
		Profile:  "dev",
		RoleARN:  "",
		Regions:  []string{"eu-west-1"},
		Services: []awsproxy.Service{{Name: "dynamodb", Mode: "ro"}},
	}}
	if !reflect.DeepEqual(cfg.AWS, wantAWS) {
		t.Errorf("AWS = %+v, want %+v", cfg.AWS, wantAWS)
	}
	wantContainer := Container{
		Runtime: "docker",
		Image:   "ghcr.io/hrntknr/sh:full",
		Mounts:  []Mount{{Source: filepath.Join(dir, "work"), Target: "/work", ReadOnly: false}},
		Environment: map[string]Env{
			"LANG": {Inherit: true},
			"FOO":  {Value: "bar"},
		},
	}
	if !reflect.DeepEqual(cfg.Container, wantContainer) {
		t.Errorf("Container = %+v, want %+v", cfg.Container, wantContainer)
	}
}

func TestLoadValid(t *testing.T) {
	tests := []struct {
		name   string
		config string
		check  func(*testing.T, Config)
	}{
		{
			name:   "minimal version only",
			config: "version: 3\n",
			check: func(t *testing.T, cfg Config) {
				if len(cfg.SSH) != 0 || len(cfg.K8s) != 0 || len(cfg.AWS) != 0 || cfg.Container.Image != "" {
					t.Fatalf("empty config should load zero values, got %+v", cfg)
				}
			},
		},
		{
			name:   "ssh without user and port",
			config: "version: 3\nssh:\n  - host: github.com\n    access: full\n",
			check: func(t *testing.T, cfg Config) {
				if cfg.SSH[0].User != "" || cfg.SSH[0].Port != 0 {
					t.Errorf("SSH[0] = %+v, want user/port unset", cfg.SSH[0])
				}
			},
		},
		{
			name:   "core group explicit empty string",
			config: "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get]\n",
			check: func(t *testing.T, cfg Config) {
				if cfg.K8s[0].Resources[0].Group != "" {
					t.Errorf("Group = %q, want empty core API group", cfg.K8s[0].Resources[0].Group)
				}
			},
		},
		{
			name:   "namespace all and scope cluster",
			config: "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: \"*\"\n        verbs: [get, list, watch]\n      - group: \"\"\n        resource: namespaces\n        scope: cluster\n        verbs: [get, list, watch]\n",
			check: func(t *testing.T, cfg Config) {
				if cfg.K8s[0].Resources[0].Namespace != "*" {
					t.Errorf("Namespace = %q, want *", cfg.K8s[0].Resources[0].Namespace)
				}
				if cfg.K8s[0].Resources[1].Scope != "cluster" || cfg.K8s[0].Resources[1].Namespace != "" {
					t.Errorf("Resources[1] = %+v, want scope cluster", cfg.K8s[0].Resources[1])
				}
			},
		},
		{
			name:   "aws with roleArn and regions omitted",
			config: "version: 3\naws:\n  - profile: dev\n    roleArn: arn:aws:iam::123456789012:role/sb-dev\n    services:\n      - name: dynamodb\n        mode: ro\n      - name: sts\n        mode: rw\n",
			check: func(t *testing.T, cfg Config) {
				if cfg.AWS[0].RoleARN != "arn:aws:iam::123456789012:role/sb-dev" || len(cfg.AWS[0].Regions) != 0 {
					t.Errorf("AWS[0] = %+v", cfg.AWS[0])
				}
				if len(cfg.AWS[0].Services) != 2 || cfg.AWS[0].Services[1] != (awsproxy.Service{Name: "sts", Mode: "rw"}) {
					t.Errorf("AWS[0].Services = %+v", cfg.AWS[0].Services)
				}
			},
		},
		{
			name:   "container runtime auto and readOnly mount",
			config: "version: 3\ncontainer:\n  runtime: auto\n  image: ghcr.io/hrntknr/sh:full\n  mounts:\n    - source: /srv/work\n      target: /work\n      readOnly: true\n",
			check: func(t *testing.T, cfg Config) {
				if !reflect.DeepEqual(cfg.Container.Mounts, []Mount{{Source: "/srv/work", Target: "/work", ReadOnly: true}}) {
					t.Errorf("Mounts = %+v, want read-only mount", cfg.Container.Mounts)
				}
				if cfg.Container.Runtime != "auto" {
					t.Errorf("Runtime = %q, want auto", cfg.Container.Runtime)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			writeFile(t, path, tt.config)
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			tt.check(t, cfg)
		})
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name   string
		config string
		wantIn string
	}{
		// v2 config: no version, old structure, or v2 values.
		{"v2 missing version", "ssh:\n  - host: github.com\n", "version is required"},
		{"v2 README config", "ssh:\n  - host: github.com\n    commands:\n      - cat\nk8s:\n  - context: dev\n    mode: rw\n    namespace: default\n", "v2 config is not accepted"},
		{"v2 commands field", "version: 3\nssh:\n  - host: github.com\n    commands: [cat]\n", "field commands not found"},
		{"v2 k8s mode field", "version: 3\nk8s:\n  - context: dev\n    mode: r\n    resources: []\n", "field mode not found"},
		{"v2 proxy section", "version: 3\nproxy:\n  sshAgentEnv: ~/.cache/sb-agent.env\n", "field proxy not found"},
		{"v2 container environments list", "version: 3\ncontainer:\n  environments:\n    - FOO=bar\n", "field environments not found"},
		{"v2 aws mode r value", "version: 3\naws:\n  - profile: dev\n    services:\n      - name: dynamodb\n        mode: r\n", `invalid mode "r" (want ro or rw)`},
		{"version 2", "version: 2\nssh:\n  - host: github.com\n    access: full\n", "unsupported version 2"},
		{"version as string", "version: \"3\"\nssh:\n  - host: github.com\n    access: full\n", "cannot unmarshal !!str"},
		{"unknown top field", "version: 3\nbogus: 1\n", "field bogus not found"},
		{"unknown ssh field", "version: 3\nssh:\n  - host: github.com\n    access: full\n    bogus: 1\n", "field bogus not found"},
		{"unknown container field", "version: 3\ncontainer:\n  bogus: 1\n", "field bogus not found"},
		// Required values must not be empty.
		{"ssh empty host", "version: 3\nssh:\n  - host: \"\"\n    access: full\n", "host is required"},
		{"ssh whitespace host", "version: 3\nssh:\n  - host: \"  \"\n    access: full\n", "host is required"},
		{"ssh missing access", "version: 3\nssh:\n  - host: github.com\n", "access is required"},
		{"ssh invalid access", "version: 3\nssh:\n  - host: github.com\n    access: limited\n", `unsupported access mode "limited"`},
		{"ssh empty user", "version: 3\nssh:\n  - host: github.com\n    user: \"\"\n    access: full\n", "user must not be empty"},
		{"ssh port zero", "version: 3\nssh:\n  - host: github.com\n    port: 0\n    access: full\n", "invalid port 0"},
		{"ssh port out of range", "version: 3\nssh:\n  - host: github.com\n    port: 70000\n    access: full\n", "invalid port 70000"},
		{"k8s empty context", "version: 3\nk8s:\n  - context: \"\"\n    resources: []\n", "context is required"},
		{"k8s missing resources", "version: 3\nk8s:\n  - context: dev\n", "resources is required"},
		{"k8s empty resource", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: \"\"\n        namespace: default\n        verbs: [get]\n", "resource is required"},
		{"k8s missing group", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - resource: pods\n        namespace: default\n        verbs: [get]\n", `group is required (use group: "" for the core API group)`},
		{"k8s whitespace group", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \" \"\n        resource: pods\n        namespace: default\n        verbs: [get]\n", `invalid group " "`},
		{"k8s missing namespace and scope", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        verbs: [get]\n", "namespace is required (or set scope: cluster"},
		{"k8s empty namespace", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: \"\"\n        verbs: [get]\n", "namespace must not be empty"},
		{"k8s namespace and scope", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        scope: cluster\n        verbs: [get]\n", "namespace and scope are mutually exclusive"},
		{"k8s invalid scope", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        scope: node\n        verbs: [get]\n", `invalid scope "node" (want cluster)`},
		{"k8s missing verbs", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n", "verbs is required"},
		{"k8s unsupported verb", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get, create]\n", `unsupported verb "create"`},
		{"k8s unsupported verb for pods/log", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods/log\n        namespace: default\n        verbs: [list]\n", `unsupported verb "list" for "pods/log"`},
		{"k8s unsupported subresource", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: deployments/scale\n        namespace: default\n        verbs: [get]\n", `unsupported subresource "deployments/scale"`},
		{"k8s duplicate verb", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get, get]\n", `duplicate verb "get"`},
		{"aws empty profile", "version: 3\naws:\n  - profile: \"\"\n    services: []\n", "profile is required"},
		{"aws invalid roleArn", "version: 3\naws:\n  - profile: dev\n    roleArn: arn:aws:iam::123456789012:role/\n    services: []\n", "invalid roleArn"},
		{"aws empty region", "version: 3\naws:\n  - profile: dev\n    regions: [\"\"]\n    services: []\n", "must not be empty"},
		{"aws missing services", "version: 3\naws:\n  - profile: dev\n", "services is required"},
		{"aws empty service name", "version: 3\naws:\n  - profile: dev\n    services:\n      - name: \"\"\n        mode: ro\n", "service name is required"},
		{"aws unsupported service", "version: 3\naws:\n  - profile: dev\n    services:\n      - name: route53\n        mode: rw\n", `unsupported service "route53"`},
		{"aws unsupported service mode", "version: 3\naws:\n  - profile: dev\n    services:\n      - name: dynamodb\n        mode: read\n", `invalid mode "read" (want ro or rw)`},
		{"aws duplicate service", "version: 3\naws:\n  - profile: dev\n    services:\n      - name: dynamodb\n        mode: ro\n      - name: dynamodb\n        mode: rw\n", `duplicate service "dynamodb"`},
		{"container image required", "version: 3\ncontainer:\n  runtime: docker\n  mounts:\n    - source: /srv/work\n      target: /work\n", "image is required when the container section is set"},
		{"container invalid runtime", "version: 3\ncontainer:\n  runtime: containerd\n  image: ghcr.io/hrntknr/sh:full\n", `invalid runtime "containerd"`},
		{"mount missing source", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  mounts:\n    - target: /work\n", "source is required"},
		{"mount relative source", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  mounts:\n    - source: work\n      target: /work\n", "source must be an absolute path"},
		{"mount missing target", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  mounts:\n    - source: /srv/work\n", "target is required"},
		{"mount relative target", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  mounts:\n    - source: /srv/work\n      target: work\n", "target must be an absolute path"},
		{"env neither inherit nor value", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  environment:\n    FOO: {}\n", "set either inherit or value"},
		{"env both inherit and value", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  environment:\n    FOO: {inherit: true, value: bar}\n", "not both"},
		{"env empty value", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  environment:\n    FOO: {value: \"\"}\n", "set either inherit or value"},
		{"env key with whitespace", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  environment:\n    \"FOO BAR\": {value: bar}\n", "key must not contain whitespace"},
		{"env yaml duplicate key", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  environment:\n    FOO: {value: bar}\n    FOO: {value: baz}\n", "already defined at line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			writeFile(t, path, tt.config)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantIn) {
				t.Fatalf("Load() error = %v, want containing %q", err, tt.wantIn)
			}
		})
	}
}

func TestLoadDuplicates(t *testing.T) {
	tests := []struct {
		name   string
		main   string
		dropIn string
		wantIn string
	}{
		{
			name:   "same ssh host in two files",
			main:   "version: 3\nssh:\n  - host: github.com\n    access: full\n",
			dropIn: "ssh:\n  - host: github.com\n    access: full\n",
			wantIn: `host "github.com" is already defined in`,
		},
		{
			name:   "same k8s context in two files",
			main:   "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get]\n",
			dropIn: "k8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get]\n",
			wantIn: `context "dev" is already defined in`,
		},
		{
			name:   "same aws profile in two files",
			main:   "version: 3\naws:\n  - profile: dev\n    services:\n      - name: dynamodb\n        mode: ro\n",
			dropIn: "aws:\n  - profile: dev\n    services:\n      - name: dynamodb\n        mode: rw\n",
			wantIn: `profile "dev" is already defined in`,
		},
		{
			name:   "same ssh host within one file",
			main:   "version: 3\nssh:\n  - host: github.com\n    access: full\n  - host: github.com\n    access: full\n",
			wantIn: `host "github.com" is already defined in`,
		},
		{
			name:   "same mount target in two files",
			main:   "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  mounts:\n    - source: /srv/a\n      target: /work\n",
			dropIn: "container:\n  mounts:\n    - source: /srv/b\n      target: /work\n",
			wantIn: `target "/work" is already defined in`,
		},
		{
			name:   "same environment variable in two files",
			main:   "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  environment:\n    FOO: {value: main}\n",
			dropIn: "container:\n  environment:\n    FOO: {value: dropin}\n",
			wantIn: `environment "FOO" is already defined in`,
		},
		{
			name:   "same image in two files",
			main:   "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n",
			dropIn: "container:\n  image: ghcr.io/hrntknr/sh:min\n",
			wantIn: "image is already defined in",
		},
		{
			name:   "same runtime in two files",
			main:   "version: 3\ncontainer:\n  runtime: docker\n  image: ghcr.io/hrntknr/sh:full\n",
			dropIn: "container:\n  runtime: podman\n",
			wantIn: "runtime is already defined in",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			writeFile(t, path, tt.main)
			if tt.dropIn != "" {
				writeFile(t, filepath.Join(dir, "conf.d", "10-work.yaml"), "version: 3\n"+tt.dropIn)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantIn) {
				t.Fatalf("Load() error = %v, want containing %q", err, tt.wantIn)
			}
		})
	}
}

func TestLoadConfD(t *testing.T) {
	t.Run("appends entries in file order", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "config.yaml"), "version: 3\nssh:\n  - host: main.example\n    access: full\n")
		writeFile(t, filepath.Join(dir, "conf.d", "20-b.yaml"), "ssh:\n  - host: b.example\n    access: full\n")
		writeFile(t, filepath.Join(dir, "conf.d", "10-a.yaml"), "ssh:\n  - host: a.example\n    access: full\n")
		cfg, err := Load(filepath.Join(dir, "config.yaml"))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		got := []string{cfg.SSH[0].Host, cfg.SSH[1].Host, cfg.SSH[2].Host}
		if want := []string{"main.example", "a.example", "b.example"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("SSH hosts = %v, want %v (main first, drop-ins sorted)", got, want)
		}
	})
	t.Run("missing directory is fine", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		writeFile(t, path, "version: 3\nssh:\n  - host: github.com\n    access: full\n")
		if _, err := Load(path); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
	})
	t.Run("ignores non-yaml, hidden, and directories", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		writeFile(t, path, "version: 3\nssh:\n  - host: github.com\n    access: full\n")
		writeFile(t, filepath.Join(dir, "conf.d", "README.md"), "ignored")
		writeFile(t, filepath.Join(dir, "conf.d", ".gitkeep"), "")
		writeFile(t, filepath.Join(dir, "conf.d", "subdir"), "") // directory
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if len(cfg.SSH) != 1 {
			t.Fatalf("SSH len = %d, want 1", len(cfg.SSH))
		}
	})
	t.Run("drop-in without version is fine", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		writeFile(t, path, "version: 3\nssh:\n  - host: github.com\n    access: full\n")
		writeFile(t, filepath.Join(dir, "conf.d", "work.yaml"), "ssh:\n  - host: work.example\n    access: full\n")
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if len(cfg.SSH) != 2 || cfg.SSH[1].Host != "work.example" {
			t.Fatalf("SSH = %+v, want the drop-in appended", cfg.SSH)
		}
	})
	t.Run("drop-in with wrong version", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		writeFile(t, path, "version: 3\n")
		writeFile(t, filepath.Join(dir, "conf.d", "work.yaml"), "version: 2\nssh: []\n")
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "unsupported version 2") {
			t.Fatalf("Load() error = %v, want unsupported version 2", err)
		}
	})
	t.Run("invalid yaml in drop-in", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		writeFile(t, path, "version: 3\n")
		writeFile(t, filepath.Join(dir, "conf.d", "bad.yaml"), "ssh: [unclosed\n")
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "conf.d/bad.yaml") {
			t.Fatalf("Load() error = %v, want it to mention conf.d/bad.yaml", err)
		}
	})
}

func TestLoadMountAmbiguity(t *testing.T) {
	tests := []struct {
		name   string
		mounts string
	}{
		{"nested targets", "  mounts:\n    - source: /srv/a\n      target: /work\n    - source: /srv/b\n      target: /work/data\n"},
		{"deep nested targets", "  mounts:\n    - source: /srv/a\n      target: /work\n    - source: /srv/b\n      target: /work/x/y\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			writeFile(t, path, "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n"+tt.mounts)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "is nested under") {
				t.Fatalf("Load() error = %v, want nested-under error", err)
			}
		})
	}
	t.Run("sibling targets are fine", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		writeFile(t, path, "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  mounts:\n    - source: /srv/a\n      target: /work\n    - source: /srv/b\n      target: /data\n")
		if _, err := Load(path); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
