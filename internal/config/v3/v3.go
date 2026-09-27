// Package v3 loads the sb v3 policy config. A v3 config starts with
// version: 3; v2 config is rejected without interpretation instead of
// being silently carried over. See docs/migration.md for conversion.
package v3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/hrntknr/sb/internal/awsproxy"
	"github.com/hrntknr/sb/internal/k8sproxy"
	"github.com/hrntknr/sb/internal/util"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
	"unicode"
)

// Config is the validated v3 policy for the ssh, k8s, and AWS proxies and
// the container settings for sb run.
type Config struct {
	SSH       []SSHRule
	K8s       []K8sRule
	AWS       []AWSRule
	Container Container
}

// SSHRule grants access to the hosts matching the Host pattern, which is
// matched against the hostname resolved on the host running sb. User and
// Port are optional restrictions on the upstream connection; empty means
// unset. Access is the access mode; "full" covers shell, any exec,
// subsystem, and TCP forwarding.
type SSHRule struct {
	Host   string
	User   string
	Port   int
	Access string
}

// K8sRule is the policy for one kubeconfig context.
type K8sRule struct {
	Context   string
	Resources []ResourceRule
}

// ResourceRule grants Verbs on one resource. Group "" is the core API
// group. Namespace is a namespace name or "*" (all namespaces); Scope
// "cluster" marks a cluster-scoped rule instead of a namespace.
type ResourceRule struct {
	Group     string
	Resource  string
	Namespace string
	Scope     string
	Verbs     []string
}

// AWSRule grants service modes to the AWS profiles matching the Profile
// pattern, restricted to Regions.
type AWSRule struct {
	Profile  string
	RoleARN  string
	Regions  []string
	Services []awsproxy.Service
}

// Container is the container section of the config.
type Container struct {
	Runtime     string
	Image       string
	Mounts      []Mount
	Environment map[string]Env
}

// Mount is one volume: Source (with ~ expanded) bound at Target.
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// Env is one environment variable: either inherited from the sb process
// or a fixed value.
type Env struct {
	Inherit bool
	Value   string
}

// document is the yaml schema of one config file.
type document struct {
	Version   *int           `yaml:"version"`
	Container *containerFile `yaml:"container"`
	SSH       []sshRule      `yaml:"ssh"`
	K8s       []k8sRule      `yaml:"k8s"`
	AWS       []awsRule      `yaml:"aws"`
}

type sshRule struct {
	Host   string  `yaml:"host"`
	User   *string `yaml:"user"`
	Port   *int    `yaml:"port"`
	Access string  `yaml:"access"`
}

type k8sRule struct {
	Context   string        `yaml:"context"`
	Resources []k8sResource `yaml:"resources"`
}

type k8sResource struct {
	Group     *string  `yaml:"group"`
	Resource  string   `yaml:"resource"`
	Namespace *string  `yaml:"namespace"`
	Scope     *string  `yaml:"scope"`
	Verbs     []string `yaml:"verbs"`
}

type awsRule struct {
	Profile  string             `yaml:"profile"`
	RoleARN  string             `yaml:"roleArn"`
	Regions  []string           `yaml:"regions"`
	Services []awsproxy.Service `yaml:"services"`
}

type containerFile struct {
	Runtime     string         `yaml:"runtime"`
	Image       string         `yaml:"image"`
	Mounts      []mountEntry   `yaml:"mounts"`
	Environment map[string]Env `yaml:"environment"`
}

type mountEntry struct {
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"readOnly"`
}

// The k8s verbs sb supports in the initial v3 version: get/list/watch for
// regular resources and get for pods/log.
var (
	regularResourceVerbs = []string{"get", "list", "watch"}
	logResourceVerbs     = []string{"get"}
)

// Load reads the v3 config at path plus any *.yaml or *.yml drop-ins in the
// conf.d directory next to it. Duplicate targets (the same ssh host, k8s
// context, or aws profile, and the same mount target or environment
// variable in two files) are errors: a drop-in no longer overrides an
// earlier definition.
func Load(path string) (Config, error) {
	path = util.ExpandHome(path)
	files, err := loadAll(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		SSH: []SSHRule{}, K8s: []K8sRule{}, AWS: []AWSRule{},
		Container: Container{Mounts: []Mount{}, Environment: map[string]Env{}},
	}
	var (
		firstHost, firstContext, firstProfile = map[string]string{}, map[string]string{}, map[string]string{}
		firstTarget, firstEnv                 = map[string]string{}, map[string]string{}
		runtimeFrom, imageFrom                = "", ""
		containerSeen                         = false
	)
	for _, f := range files {
		for i, d := range f.doc.SSH {
			rule, err := buildSSH(d)
			if err != nil {
				return Config{}, fmt.Errorf("%s: ssh target %d: %w", f.path, i, err)
			}
			if first, ok := firstHost[rule.Host]; ok {
				return Config{}, fmt.Errorf("%s: ssh target %d: host %q is already defined in %s", f.path, i, rule.Host, first)
			}
			firstHost[rule.Host] = f.path
			cfg.SSH = append(cfg.SSH, rule)
		}
		for i, d := range f.doc.K8s {
			rule, err := buildK8s(d)
			if err != nil {
				return Config{}, fmt.Errorf("%s: k8s target %d: %w", f.path, i, err)
			}
			if first, ok := firstContext[rule.Context]; ok {
				return Config{}, fmt.Errorf("%s: k8s target %d: context %q is already defined in %s", f.path, i, rule.Context, first)
			}
			firstContext[rule.Context] = f.path
			cfg.K8s = append(cfg.K8s, rule)
		}
		for i, d := range f.doc.AWS {
			rule, err := buildAWS(d)
			if err != nil {
				return Config{}, fmt.Errorf("%s: aws target %d: %w", f.path, i, err)
			}
			if first, ok := firstProfile[rule.Profile]; ok {
				return Config{}, fmt.Errorf("%s: aws target %d: profile %q is already defined in %s", f.path, i, rule.Profile, first)
			}
			firstProfile[rule.Profile] = f.path
			cfg.AWS = append(cfg.AWS, rule)
		}
		if d := f.doc.Container; d != nil {
			containerSeen = true
			for i, m := range d.Mounts {
				mount, err := buildMount(m)
				if err != nil {
					return Config{}, fmt.Errorf("%s: container mount %d: %w", f.path, i, err)
				}
				if first, ok := firstTarget[mount.Target]; ok {
					return Config{}, fmt.Errorf("%s: container mount %d: target %q is already defined in %s", f.path, i, mount.Target, first)
				}
				firstTarget[mount.Target] = f.path
				cfg.Container.Mounts = append(cfg.Container.Mounts, mount)
			}
			for _, key := range slices.Sorted(maps.Keys(d.Environment)) {
				env := d.Environment[key]
				if err := validateEnvKey(key); err != nil {
					return Config{}, fmt.Errorf("%s: container environment %q: %w", f.path, key, err)
				}
				if err := validateEnvValue(env); err != nil {
					return Config{}, fmt.Errorf("%s: container environment %q: %w", f.path, key, err)
				}
				if first, ok := firstEnv[key]; ok {
					return Config{}, fmt.Errorf("%s: container environment %q is already defined in %s", f.path, key, first)
				}
				firstEnv[key] = f.path
				cfg.Container.Environment[key] = env
			}
			if runtime := strings.TrimSpace(d.Runtime); runtime != "" {
				if err := validateRuntime(runtime); err != nil {
					return Config{}, fmt.Errorf("%s: container: %w", f.path, err)
				}
				if runtimeFrom != "" {
					return Config{}, fmt.Errorf("%s: container: runtime is already defined in %s", f.path, runtimeFrom)
				}
				runtimeFrom = f.path
				cfg.Container.Runtime = runtime
			}
			if d.Image != "" {
				// A value that is present but whitespace-only is a broken
				// definition, not an omission: without this check it would
				// silently lose to an image in another file.
				image := strings.TrimSpace(d.Image)
				if image == "" {
					return Config{}, fmt.Errorf("%s: container: image must not be whitespace-only", f.path)
				}
				if imageFrom != "" {
					return Config{}, fmt.Errorf("%s: container: image is already defined in %s", f.path, imageFrom)
				}
				imageFrom = f.path
				cfg.Container.Image = image
			}
		}
	}
	if containerSeen && cfg.Container.Image == "" {
		return Config{}, errors.New("container: image is required when the container section is set")
	}
	for i, mount := range cfg.Container.Mounts {
		for j := range cfg.Container.Mounts {
			if i == j {
				continue
			}
			if strings.HasPrefix(mount.Target, cfg.Container.Mounts[j].Target+string(filepath.Separator)) {
				return Config{}, fmt.Errorf("container mounts: target %q is nested under %q", mount.Target, cfg.Container.Mounts[j].Target)
			}
		}
	}
	return cfg, nil
}

func buildSSH(d sshRule) (SSHRule, error) {
	if strings.TrimSpace(d.Host) == "" {
		return SSHRule{}, errors.New("host is required")
	}
	if err := noWhitespace("host", d.Host); err != nil {
		return SSHRule{}, err
	}
	if d.User != nil && strings.TrimSpace(*d.User) == "" {
		return SSHRule{}, errors.New("user must not be empty")
	}
	if d.Port != nil && (*d.Port < 1 || *d.Port > 65535) {
		return SSHRule{}, fmt.Errorf("invalid port %d (want 1-65535)", *d.Port)
	}
	if d.Access != "full" {
		if d.Access == "" {
			return SSHRule{}, errors.New("access is required (supported: full)")
		}
		return SSHRule{}, fmt.Errorf("unsupported access mode %q (supported: full)", d.Access)
	}
	rule := SSHRule{Host: d.Host, Access: "full"}
	if d.User != nil {
		rule.User = *d.User
	}
	if d.Port != nil {
		rule.Port = *d.Port
	}
	return rule, nil
}

func buildK8s(d k8sRule) (K8sRule, error) {
	if strings.TrimSpace(d.Context) == "" {
		return K8sRule{}, errors.New("context is required")
	}
	if len(d.Resources) == 0 {
		return K8sRule{}, errors.New("resources is required (empty permission)")
	}
	resources := make([]ResourceRule, 0, len(d.Resources))
	for i, r := range d.Resources {
		rule, err := buildResource(r)
		if err != nil {
			return K8sRule{}, fmt.Errorf("resource %d: %w", i, err)
		}
		resources = append(resources, rule)
	}
	return K8sRule{Context: d.Context, Resources: resources}, nil
}

func buildResource(d k8sResource) (ResourceRule, error) {
	if d.Group == nil {
		return ResourceRule{}, errors.New(`group is required (use group: "" for the core API group)`)
	}
	if err := noWhitespace("group", *d.Group); err != nil {
		return ResourceRule{}, err
	}
	if strings.TrimSpace(d.Resource) == "" {
		return ResourceRule{}, errors.New("resource is required")
	}
	if err := noWhitespace("resource", d.Resource); err != nil {
		return ResourceRule{}, err
	}
	if strings.Contains(d.Resource, "/") && d.Resource != "pods/log" {
		return ResourceRule{}, fmt.Errorf("unsupported subresource %q (only pods/log is supported)", d.Resource)
	}
	if d.Scope != nil && *d.Scope != "cluster" {
		return ResourceRule{}, fmt.Errorf("invalid scope %q (want cluster)", *d.Scope)
	}
	// The rule's shape must match the scope the Kubernetes API gives
	// the resource: a cluster-scoped one takes scope: cluster, a
	// namespaced one a namespace.
	if clusterScoped, known := k8sproxy.CoreResourceScope(*d.Group, d.Resource); known {
		if clusterScoped {
			if d.Namespace != nil {
				return ResourceRule{}, fmt.Errorf("%s is cluster-scoped: give scope: cluster, not a namespace", d.Resource)
			}
			if d.Scope == nil {
				return ResourceRule{}, fmt.Errorf("%s is cluster-scoped: give scope: cluster", d.Resource)
			}
		} else if d.Scope != nil {
			return ResourceRule{}, fmt.Errorf("%s is namespaced: give a namespace, not scope: cluster", d.Resource)
		}
	}
	if d.Namespace == nil && d.Scope == nil {
		return ResourceRule{}, errors.New("namespace is required (or set scope: cluster for cluster-scoped resources)")
	}
	if d.Namespace != nil && d.Scope != nil {
		return ResourceRule{}, errors.New("namespace and scope are mutually exclusive")
	}
	if d.Namespace != nil && strings.TrimSpace(*d.Namespace) == "" {
		return ResourceRule{}, errors.New("namespace must not be empty")
	}
	if d.Namespace != nil && *d.Namespace != "*" {
		if errs := validation.IsDNS1123Label(*d.Namespace); len(errs) > 0 {
			return ResourceRule{}, fmt.Errorf("invalid namespace %q (%s)", *d.Namespace, strings.Join(errs, ", "))
		}
	}
	if len(d.Verbs) == 0 {
		return ResourceRule{}, errors.New("verbs is required (empty permission)")
	}
	supported := regularResourceVerbs
	if d.Resource == "pods/log" {
		supported = logResourceVerbs
	}
	seen := make(map[string]bool, len(d.Verbs))
	for _, verb := range d.Verbs {
		if !slices.Contains(supported, verb) {
			return ResourceRule{}, fmt.Errorf("unsupported verb %q for %q (supported: %s)", verb, d.Resource, strings.Join(supported, ", "))
		}
		if seen[verb] {
			return ResourceRule{}, fmt.Errorf("duplicate verb %q", verb)
		}
		seen[verb] = true
	}
	rule := ResourceRule{Group: *d.Group, Resource: d.Resource, Verbs: d.Verbs}
	if d.Namespace != nil {
		rule.Namespace = *d.Namespace
	}
	if d.Scope != nil {
		rule.Scope = *d.Scope
	}
	return rule, nil
}

func buildAWS(d awsRule) (AWSRule, error) {
	if strings.TrimSpace(d.Profile) == "" {
		return AWSRule{}, errors.New("profile is required")
	}
	if err := noWhitespace("profile", d.Profile); err != nil {
		return AWSRule{}, err
	}
	if d.RoleARN != "" && !awsproxy.ValidRoleARN(d.RoleARN) {
		return AWSRule{}, fmt.Errorf("invalid roleArn %q", d.RoleARN)
	}
	for i, region := range d.Regions {
		if strings.TrimSpace(region) == "" {
			return AWSRule{}, fmt.Errorf("region %d: must not be empty", i)
		}
		if err2 := noWhitespace("region", region); err2 != nil {
			return AWSRule{}, fmt.Errorf("region %d: %w", i, err2)
		}
	}
	if len(d.Services) == 0 {
		return AWSRule{}, errors.New("services is required (empty permission)")
	}
	services := make([]awsproxy.Service, 0, len(d.Services))
	seen := make(map[string]bool, len(d.Services))
	for _, s := range d.Services {
		if strings.TrimSpace(s.Name) == "" {
			return AWSRule{}, errors.New("service name is required")
		}
		if !awsproxy.ValidServiceName(s.Name) {
			return AWSRule{}, fmt.Errorf("unsupported service %q", s.Name)
		}
		if s.Mode != "ro" && s.Mode != "rw" {
			return AWSRule{}, fmt.Errorf("invalid mode %q (want ro or rw)", s.Mode)
		}
		if seen[s.Name] {
			return AWSRule{}, fmt.Errorf("duplicate service %q", s.Name)
		}
		seen[s.Name] = true
		services = append(services, s)
	}
	return AWSRule{Profile: d.Profile, RoleARN: d.RoleARN, Regions: d.Regions, Services: services}, nil
}

func buildMount(d mountEntry) (Mount, error) {
	source := util.ExpandHome(d.Source)
	if strings.TrimSpace(source) == "" {
		return Mount{}, errors.New("source is required")
	}
	if !filepath.IsAbs(source) {
		return Mount{}, fmt.Errorf("source must be an absolute path: %q", d.Source)
	}
	if strings.TrimSpace(d.Target) == "" {
		return Mount{}, errors.New("target is required")
	}
	if !filepath.IsAbs(d.Target) {
		return Mount{}, fmt.Errorf("target must be an absolute path: %q", d.Target)
	}
	// The target is compared for duplicates and nesting as a container
	// path: /work/ and /other/../work are the same mount as /work, and
	// mounting over the container root is not a mount at all.
	target := filepath.Clean(d.Target)
	if target == "/" {
		return Mount{}, errors.New(`target must not be "/"`)
	}
	return Mount{Source: source, Target: target, ReadOnly: d.ReadOnly}, nil
}

// noWhitespace rejects values that cannot match a real name: patterns are
// matched with util.Match, which trims and compares against names that
// never contain whitespace, so a whitespace pattern never matches anything.
// unicode.IsSpace also rejects U+00A0, \v, \f and other Unicode whitespace
// that the same TrimSpace would strip, which plain " \t\r\n" misses.
func noWhitespace(field, value string) error {
	if strings.ContainsFunc(value, unicode.IsSpace) {
		return fmt.Errorf("invalid %s %q (must not contain whitespace)", field, value)
	}
	return nil
}

func validateEnvKey(key string) error {
	if key == "" {
		return errors.New("key is required")
	}
	if strings.ContainsAny(key, " \t\r\n") {
		return errors.New("key must not contain whitespace")
	}
	if strings.Contains(key, "=") {
		return errors.New(`key must not contain "="`)
	}
	return nil
}

func validateEnvValue(env Env) error {
	if env.Inherit {
		if env.Value != "" {
			return errors.New("set either inherit or value, not both")
		}
	} else if env.Value == "" {
		return errors.New("set either inherit or value")
	}
	return nil
}

func validateRuntime(runtime string) error {
	switch runtime {
	case "auto", "docker", "podman", "apple":
		return nil
	default:
		return fmt.Errorf("invalid runtime %q (want docker, podman, apple, or auto)", runtime)
	}
}

func loadAll(path string) ([]loadedDoc, error) {
	main, err := loadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	files := []loadedDoc{{path: path, doc: main}}
	if err := loadConfDir(filepath.Join(filepath.Dir(path), "conf.d"), &files); err != nil {
		return nil, err
	}
	return files, nil
}

type loadedDoc struct {
	path string
	doc  document
}

// loadConfDir appends the *.yaml and *.yml drop-ins in dir, in sorted
// order, to files.
func loadConfDir(dir string, files *[]loadedDoc) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read conf.d: %w", err)
	}
	names := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if ext := filepath.Ext(name); ext != ".yaml" && ext != ".yml" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		doc, err := loadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Join(dir, name), err)
		}
		*files = append(*files, loadedDoc{path: filepath.Join(dir, name), doc: doc})
	}
	return nil
}

// parseErr wraps a yaml decoding error; strict decoding failures point at
// the migration guide (v2 config is not accepted).
func parseErr(err error) error {
	if errors.As(err, new(*yaml.TypeError)) {
		return fmt.Errorf("parse config: %w\n(v2 config is not accepted; see docs/migration.md)", err)
	}
	return fmt.Errorf("parse config: %w", err)
}

func loadFile(path string) (document, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return document{}, fmt.Errorf("read config: %w", err)
	}
	var doc document
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return document{}, parseErr(err)
	}
	// A file is exactly one yaml document: a second document, even a
	// valid or v2-formatted one, is rejected instead of silently ignored.
	var second document
	if err2 := decoder.Decode(&second); !errors.Is(err2, io.EOF) {
		if err2 == nil {
			return document{}, errors.New("parse config: multiple yaml documents (only one document per file)")
		}
		return document{}, parseErr(err2)
	}
	if doc.Version == nil {
		return document{}, errors.New("version is required: sb reads v3 config only (version: 3); v2 config is not accepted (see docs/migration.md)")
	}
	if *doc.Version != 3 {
		return document{}, fmt.Errorf("unsupported version %d (want 3)", *doc.Version)
	}
	return doc, nil
}
