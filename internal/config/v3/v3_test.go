package v3

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/hrntknr/sb/internal/awsproxy"
	"github.com/hrntknr/sb/internal/k8sproxy"
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
			name:   "aws profile and region patterns",
			config: "version: 3\naws:\n  - profile: \"dev-*\"\n    regions: [\"eu-*\"]\n    services:\n      - name: dynamodb\n        mode: ro\n",
			check: func(t *testing.T, cfg Config) {
				if cfg.AWS[0].Profile != "dev-*" || len(cfg.AWS[0].Regions) != 1 || cfg.AWS[0].Regions[0] != "eu-*" {
					t.Errorf("AWS = %+v, want pattern profile and region", cfg.AWS)
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
		{
			name:   "ssh host wildcards",
			config: "version: 3\nssh:\n  - host: \"*.example.net\"\n    access: full\n  - host: \"*\"\n    access: full\n",
			check: func(t *testing.T, cfg Config) {
				if cfg.SSH[0].Host != "*.example.net" || cfg.SSH[1].Host != "*" {
					t.Errorf("SSH = %+v, want wildcard patterns", cfg.SSH)
				}
			},
		},
		{
			name:   "k8s namespace and verbs omitted",
			config: "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        # namespace omitted: all namespaces\n        # verbs omitted: all verbs\n      - group: \"\"\n        resource: pods/log\n        # namespace and verbs omitted\n",
			check: func(t *testing.T, cfg Config) {
				// An omitted namespace is all namespaces ("*") and an
				// omitted verbs list every verb the resource supports:
				// the seven for a regular resource, get only for a log.
				pods := cfg.K8s[0].Resources[0]
				if pods.Namespace != "*" {
					t.Errorf("pods = %+v, want namespace \"*\"", pods)
				}
				if !reflect.DeepEqual(pods.Verbs, regularResourceVerbs) {
					t.Errorf("pods.Verbs = %v, want %v (all verbs)", pods.Verbs, regularResourceVerbs)
				}
				log := cfg.K8s[0].Resources[1]
				if log.Namespace != "*" || !reflect.DeepEqual(log.Verbs, logResourceVerbs) {
					t.Errorf("pods/log = %+v, want all namespaces and %v", log, logResourceVerbs)
				}
			},
		},
		{
			name:   "k8s mode shorthand",
			config: "version: 3\nk8s:\n  - context: dev\n    mode: ro\n  - context: prod\n    mode: rw\n",
			check: func(t *testing.T, cfg Config) {
				// The shorthand keeps the mode it was written in: the
				// expansion happens where the proxy targets are built.
				if cfg.K8s[0].Mode != "ro" || len(cfg.K8s[0].Resources) != 0 {
					t.Errorf("K8s[0] = %+v, want mode ro and no resources", cfg.K8s[0])
				}
				if cfg.K8s[1].Mode != "rw" || len(cfg.K8s[1].Resources) != 0 {
					t.Errorf("K8s[1] = %+v, want mode rw and no resources", cfg.K8s[1])
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

// stableResources lists every resource of every group the Kubernetes
// stable API at v1.36 has, with the scope the API reference gives it —
// an independent list, written from the reference docs, that the scope
// table has to answer for: a resource the table misses answers here
// instead, and one it maps to the wrong scope answers here too.
var stableResources = []struct {
	group    string
	resource string
	cluster  bool // cluster-scoped as the API reference gives it
}{
	{"", "bindings", false},
	{"", "componentstatuses", true},
	{"", "configmaps", false},
	{"", "endpoints", false},
	{"", "events", false},
	{"", "limitranges", false},
	{"", "namespaces", true},
	{"", "nodes", true},
	{"", "persistentvolumeclaims", false},
	{"", "persistentvolumes", true},
	{"", "pods", false},
	{"", "podtemplates", false},
	{"", "replicationcontrollers", false},
	{"", "resourcequotas", false},
	{"", "secrets", false},
	{"", "serviceaccounts", false},
	{"", "services", false},
	{"apps", "controllerrevisions", false},
	{"apps", "daemonsets", false},
	{"apps", "deployments", false},
	{"apps", "replicasets", false},
	{"apps", "statefulsets", false},
	{"admissionregistration.k8s.io", "mutatingwebhookconfigurations", true},
	{"admissionregistration.k8s.io", "mutatingadmissionpolicies", true},
	{"admissionregistration.k8s.io", "mutatingadmissionpolicybindings", true},
	{"admissionregistration.k8s.io", "validatingwebhookconfigurations", true},
	{"admissionregistration.k8s.io", "validatingadmissionpolicies", true},
	{"admissionregistration.k8s.io", "validatingadmissionpolicybindings", true},
	{"apiextensions.k8s.io", "customresourcedefinitions", true},
	{"apiregistration.k8s.io", "apiservices", true},
	{"authentication.k8s.io", "selfsubjectreviews", true},
	{"authentication.k8s.io", "tokenreviews", true},
	{"authorization.k8s.io", "localsubjectaccessreviews", false},
	{"authorization.k8s.io", "selfsubjectaccessreviews", true},
	{"authorization.k8s.io", "selfsubjectrulesreviews", true},
	{"authorization.k8s.io", "subjectaccessreviews", true},
	{"autoscaling", "horizontalpodautoscalers", false},
	{"batch", "cronjobs", false},
	{"batch", "jobs", false},
	{"certificates.k8s.io", "certificatesigningrequests", true},
	{"coordination.k8s.io", "leases", false},
	{"discovery.k8s.io", "endpointslices", false},
	{"events.k8s.io", "events", false},
	{"flowcontrol.apiserver.k8s.io", "flowschemas", true},
	{"flowcontrol.apiserver.k8s.io", "prioritylevelconfigurations", true},
	{"networking.k8s.io", "ingressclasses", true},
	{"networking.k8s.io", "ingresses", false},
	{"networking.k8s.io", "ipaddresses", true},
	{"networking.k8s.io", "networkpolicies", false},
	{"networking.k8s.io", "servicecidrs", true},
	{"node.k8s.io", "runtimeclasses", true},
	{"policy", "poddisruptionbudgets", false},
	{"rbac.authorization.k8s.io", "clusterrolebindings", true},
	{"rbac.authorization.k8s.io", "clusterroles", true},
	{"rbac.authorization.k8s.io", "rolebindings", false},
	{"rbac.authorization.k8s.io", "roles", false},
	{"resource.k8s.io", "deviceclasses", true},
	{"resource.k8s.io", "resourceclaims", false},
	{"resource.k8s.io", "resourceclaimtemplates", false},
	{"resource.k8s.io", "resourceslices", true},
	{"scheduling.k8s.io", "priorityclasses", true},
	{"storage.k8s.io", "csidrivers", true},
	{"storage.k8s.io", "csinodes", true},
	{"storage.k8s.io", "csistoragecapacities", false},
	{"storage.k8s.io", "storageclasses", true},
	{"storage.k8s.io", "volumeattachments", true},
	{"storage.k8s.io", "volumeattributesclasses", true},
}

// TestLoadScopeDecidedInEveryGroup covers the shape check against the
// stable API itself: every resource of every group sb decides loads
// with the shape the Kubernetes API gives it, and the reversed shape
// is rejected. The list the test runs on is independent of the scope
// table — a resource the table misses, or maps to the wrong scope,
// fails here.
func TestLoadScopeDecidedInEveryGroup(t *testing.T) {
	for _, r := range stableResources {
		t.Run(r.group+"/"+r.resource, func(t *testing.T) {
			head := fmt.Sprintf("version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: %q\n        resource: %s\n", r.group, r.resource)
			clusterShape := "        scope: cluster\n"
			namespaceShape := "        namespace: default\n"
			verbs := "        verbs: [get]\n"
			correct := head + clusterShape
			namespaced := head + namespaceShape
			if !r.cluster {
				correct, namespaced = namespaced, correct
			}
			// The shape the API gives the resource loads, and the
			// rule comes out with that shape.
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			writeFile(t, path, correct+verbs)
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load() with the %s shape: %v", shapeWord(r.cluster), err)
			}
			rule := cfg.K8s[0].Resources[0]
			if r.cluster {
				if rule.Scope != "cluster" || rule.Namespace != "" {
					t.Fatalf("rule = %+v, want scope: cluster", rule)
				}
			} else if rule.Namespace != "default" || rule.Scope != "" {
				t.Fatalf("rule = %+v, want namespace: default", rule)
			}
			// The reversed shape is rejected: the rule's shape must
			// match the scope the Kubernetes API gives the resource.
			dir2 := t.TempDir()
			path2 := filepath.Join(dir2, "config.yaml")
			writeFile(t, path2, namespaced+verbs)
			_, err = Load(path2)
			if err == nil {
				t.Fatalf("Load() with the reversed shape: %v; want a refusal", err)
			}
			if r.cluster {
				if !strings.Contains(err.Error(), r.resource+" is cluster-scoped: give scope: cluster, not a namespace") {
					t.Fatalf("Load() with the reversed shape: %v", err)
				}
			} else if !strings.Contains(err.Error(), r.resource+" is namespaced: give a namespace, not scope: cluster") {
				t.Fatalf("Load() with the reversed shape: %v", err)
			}
		})
	}
}

// shapeWord names the shape the correct rule takes: cluster-scoped or
// namespaced.
func shapeWord(cluster bool) string {
	if cluster {
		return "cluster-scoped"
	}
	return "namespaced"
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
		{"k8s invalid mode value", "version: 3\nk8s:\n  - context: dev\n    mode: read\n    resources: []\n", `invalid mode "read" (want ro or rw)`},
		{"k8s mode and resources", "version: 3\nk8s:\n  - context: dev\n    mode: rw\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get]\n", "mode and resources are mutually exclusive"},
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
		{"k8s empty namespace", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: \"\"\n        verbs: [get]\n", "namespace must not be empty"},
		{"k8s namespace and scope", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        scope: cluster\n        verbs: [get]\n", "give a namespace, not scope: cluster"},
		{"k8s cluster-scoped with a namespace", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: nodes\n        namespace: default\n        verbs: [get]\n", "nodes is cluster-scoped: give scope: cluster, not a namespace"},
		{"k8s cluster-scoped without scope", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: namespaces\n        verbs: [get]\n", "namespaces is cluster-scoped: give scope: cluster"},
		// The shape must match beyond the core group too: what sb
		// decides in apps and rbac it decides the same way.
		{"k8s apps namespaced with scope cluster", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: apps\n        resource: deployments\n        scope: cluster\n        verbs: [list]\n", "deployments is namespaced: give a namespace, not scope: cluster"},
		{"k8s rbac cluster-scoped with a namespace", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: rbac.authorization.k8s.io\n        resource: clusterroles\n        namespace: \"*\"\n        verbs: [list]\n", "clusterroles is cluster-scoped: give scope: cluster, not a namespace"},
		// What sb does not decide the scope of is not loadable:
		// the rule could not be checked against the resource's real
		// scope, so the config would promise more than the
		// authorization grants.
		{"k8s undecided resource", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: example.com\n        resource: widgets\n        namespace: default\n        verbs: [get]\n", "not one sb decides the scope of"},
		{"k8s undecided core resource", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: inventions\n        namespace: default\n        verbs: [get]\n", "not one sb decides the scope of"},
		{"k8s invalid scope", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        scope: node\n        verbs: [get]\n", `invalid scope "node" (want cluster)`},
		{"k8s unsupported verb", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get, deletecollection]\n", `unsupported verb "deletecollection"`},
		{"k8s unsupported verb full list", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get, list, watch, create, update, patch, delete, impersonate]\n", `unsupported verb "impersonate"`},
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
		{"env key with equals", "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n  environment:\n    A=B: {value: bar}\n", `key must not contain "="`},
		{"ssh host with whitespace", "version: 3\nssh:\n  - host: bad host\n    access: full\n", "must not contain whitespace"},
		{"k8s namespace with slash", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: bad/name\n        verbs: [get]\n", "invalid namespace"},
		{"k8s namespace uppercase", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: Default\n        verbs: [get]\n", "invalid namespace"},
		{"k8s namespace too long", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: " + strings.Repeat("a", 64) + "\n        verbs: [get]\n", "invalid namespace"},
		{"k8s resource with whitespace", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: bad resource\n        namespace: default\n        verbs: [get]\n", "must not contain whitespace"},
		{"k8s group with whitespace", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: bad group\n        resource: pods\n        namespace: default\n        verbs: [get]\n", "must not contain whitespace"},
		{"aws profile with whitespace", "version: 3\naws:\n  - profile: bad profile\n    services: []\n", "must not contain whitespace"},
		{"aws region with whitespace", "version: 3\naws:\n  - profile: dev\n    regions: [\"eu west\"]\n    services: []\n", "must not contain whitespace"},
		{"container image whitespace only", "version: 3\ncontainer:\n  runtime: docker\n  image: \"   \"\n", "image must not be whitespace-only"},
		{"second yaml document", "version: 3\nssh:\n  - host: a.example\n    access: full\n---\nssh:\n  - host: b.example\n    access: full\n", "multiple yaml documents"},
		{"second document v2 format", "version: 3\nssh:\n  - host: a.example\n    access: full\n---\nssh:\n  - host: b.example\n    commands: [cat]\n", "field commands not found"},
		{"trailing syntax error", "version: 3\nssh:\n  - host: a.example\n    access: full\n---\nssh: [unclosed\n", "parse config"},
		// unicode.IsSpace covers U+00A0, \v (U+000B) and \f (U+000C),
		// which " \t\r\n" does not.
		{"ssh host with nbsp", "version: 3\nssh:\n  - host: \"bad\\u00a0host\"\n    access: full\n", "must not contain whitespace"},
		{"ssh host with vertical tab", "version: 3\nssh:\n  - host: \"bad\\vhost\"\n    access: full\n", "must not contain whitespace"},
		{"ssh host with form feed", "version: 3\nssh:\n  - host: \"bad\\fhost\"\n    access: full\n", "must not contain whitespace"},
		{"k8s group with nbsp", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"bad\\u00a0group\"\n        resource: pods\n        namespace: default\n        verbs: [get]\n", "must not contain whitespace"},
		{"k8s resource with nbsp", "version: 3\nk8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: \"pods\\u00a0\"\n        namespace: default\n        verbs: [get]\n", "must not contain whitespace"},
		{"aws profile with nbsp", "version: 3\naws:\n  - profile: \"bad\\u00a0profile\"\n    services:\n      - name: dynamodb\n        mode: ro\n", "must not contain whitespace"},
		{"aws region with nbsp", "version: 3\naws:\n  - profile: dev\n    regions: [\"eu\\u00a0west\"]\n    services:\n      - name: dynamodb\n        mode: ro\n", "must not contain whitespace"},
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
		{
			name:   "whitespace-only image in drop-in",
			main:   "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n",
			dropIn: "container:\n  image: \"   \"\n",
			wantIn: "image must not be whitespace-only",
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
		writeFile(t, filepath.Join(dir, "conf.d", "20-b.yaml"), "version: 3\nssh:\n  - host: b.example\n    access: full\n")
		writeFile(t, filepath.Join(dir, "conf.d", "10-a.yaml"), "version: 3\nssh:\n  - host: a.example\n    access: full\n")
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
	t.Run("drop-in without version", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		writeFile(t, path, "version: 3\nssh:\n  - host: github.com\n    access: full\n")
		writeFile(t, filepath.Join(dir, "conf.d", "work.yaml"), "ssh:\n  - host: work.example\n    access: full\n")
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "version is required") || !strings.Contains(err.Error(), "conf.d/work.yaml") {
			t.Fatalf("Load() error = %v, want version-required error mentioning conf.d/work.yaml", err)
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
		wantIn string
	}{
		{"nested targets", "  mounts:\n    - source: /srv/a\n      target: /work\n    - source: /srv/b\n      target: /work/data\n", "is nested under"},
		{"deep nested targets", "  mounts:\n    - source: /srv/a\n      target: /work\n    - source: /srv/b\n      target: /work/x/y\n", "is nested under"},
		{"same target with trailing slash", "  mounts:\n    - source: /srv/a\n      target: /work\n    - source: /srv/b\n      target: /work/\n", `target "/work" is already defined in`},
		{"same target via parent jump", "  mounts:\n    - source: /srv/a\n      target: /work\n    - source: /srv/b\n      target: /other/../work\n", `target "/work" is already defined in`},
		{"nested targets with trailing slash", "  mounts:\n    - source: /srv/a\n      target: /work/\n    - source: /srv/b\n      target: /work/data\n", "is nested under"},
		{"root target", "  mounts:\n    - source: /srv/a\n      target: /\n", `target must not be "/"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			writeFile(t, path, "version: 3\ncontainer:\n  image: ghcr.io/hrntknr/sh:full\n"+tt.mounts)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantIn) {
				t.Fatalf("Load() error = %v, want containing %q", err, tt.wantIn)
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

// The yaml blocks in docs/migration.md, and the conversion examples'
// two sides: each example is a v2 block, the "becomes:" separator, and
// the v3 conversion.
var (
	yamlBlockRe   = regexp.MustCompile("(?s)```yaml\n(.*?)\n```")
	examplePairRe = regexp.MustCompile("(?s)v2:\n\n```yaml\n(.*?)\n```\n\nbecomes:\n\nv3:\n\n```yaml\n(.*?)\n```")
)

// TestK8sTargetsModeExpansion covers the shorthand's conversion: a mode
// rule becomes a grant on every resource of the stable API, at the scope
// shape the resource's own scope table entry gives it — "*" for a
// namespaced one, "cluster" for a cluster-scoped one — with the mode's
// verbs: ro reads, rw everything. The list the expansion runs on keeps
// its order, and nothing the scope table decides is left out.
func TestK8sTargetsModeExpansion(t *testing.T) {
	ro := Config{K8s: []K8sRule{{Context: "dev", Mode: "ro"}}}
	rw := Config{K8s: []K8sRule{{Context: "dev", Mode: "rw"}}}
	roResources := ro.K8sTargets()[0].Resources
	rwResources := rw.K8sTargets()[0].Resources
	all := k8sproxy.AllResources()
	if len(roResources) != len(all) {
		t.Fatalf("mode: ro expands to %d resources, want %d (every resource of the stable API)", len(roResources), len(all))
	}
	if len(rwResources) != len(all) {
		t.Fatalf("mode: rw expands to %d resources, want %d", len(rwResources), len(all))
	}
	for i, r := range all {
		roRule, rwRule := roResources[i], rwResources[i]
		if roRule.Group != r.Group || roRule.Resource != r.Resource {
			t.Fatalf("resource %d = %s/%s, want %s/%s (the expansion keeps the list's order)", i, roRule.Group, roRule.Resource, r.Group, r.Resource)
		}
		if r.ClusterScoped {
			if roRule.Scope != "cluster" || roRule.Namespace != "" {
				t.Errorf("%s/%s = %+v, want scope cluster", r.Group, r.Resource, roRule)
			}
		} else if roRule.Namespace != "*" || roRule.Scope != "" {
			t.Errorf("%s/%s = %+v, want namespace \"*\"", r.Group, r.Resource, roRule)
		}
		if !reflect.DeepEqual(roRule.Verbs, readResourceVerbs) {
			t.Errorf("%s/%s ro verbs = %v, want %v", r.Group, r.Resource, roRule.Verbs, readResourceVerbs)
		}
		if !reflect.DeepEqual(rwRule.Verbs, regularResourceVerbs) {
			t.Errorf("%s/%s rw verbs = %v, want %v", r.Group, r.Resource, rwRule.Verbs, regularResourceVerbs)
		}
	}
}

// The conversion examples in docs/migration.md: the v3 sides must load
// through the config loader exactly as the doc shows them, and the v2
// sides must be rejected — the same rejection the doc tells the reader
// to expect. The complete example at the top loads as-is.
func TestMigrationDocExamples(t *testing.T) {
	// The doc is at the repository root: the package sits three levels
	// under it (internal/config/v3).
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "migration.md"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(doc)

	// The complete example at the top: it loads as-is.
	blocks := yamlBlockRe.FindAllStringSubmatch(content, -1)
	if len(blocks) == 0 {
		t.Fatal("no yaml blocks in docs/migration.md")
	}
	if _, err := loadDocYAML(t, blocks[0][1], ""); err != nil {
		t.Fatalf("the complete example: Load() error = %v", err)
	}

	// Each conversion example: the v3 side loads (the doc shows the
	// section; the version header the complete example carries is
	// added for it), and the v2 side is rejected.
	pairs := examplePairRe.FindAllStringSubmatch(content, -1)
	if len(pairs) != 6 {
		t.Fatalf("found %d conversion examples in docs/migration.md; want 6 — update this count when the doc changes", len(pairs))
	}
	for i, pair := range pairs {
		if _, err := loadDocYAML(t, pair[1], "version: 3\n"); err == nil {
			t.Fatalf("example %d: the v2 side loaded; want it rejected (v2 is not a v3 config)", i+1)
		}
		if _, err := loadDocYAML(t, pair[2], "version: 3\n"); err != nil {
			t.Fatalf("example %d: the v3 side: Load() error = %v", i+1, err)
		}
	}
}

// loadDocYAML loads yaml as a config: header is prepended, so a doc's
// section loads the way the complete example does.
func loadDocYAML(t *testing.T, yaml, header string) (Config, error) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir) // the examples mount from ~; keep the expansion in the test
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, header+yaml)
	return Load(path)
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
