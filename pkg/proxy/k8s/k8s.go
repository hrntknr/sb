package k8s

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/hrntknr/secretbridge/pkg/util"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/tools/clientcmd"
)

type Verb string

const (
	Read      Verb = "r"
	ReadWrite Verb = "rw"
)

// Target grants Mode access to clusters matching the Cluster glob. A nil
// Namespaces allows any namespace; otherwise only listed namespace globs are
// allowed. ClusterScope permits cluster-scoped (non-namespaced) requests.
type Target struct {
	Mode         Verb
	Cluster      string
	Namespaces   []string
	ClusterScope bool
}
type Targets []Target

func (t Targets) Allows(verb Verb, cluster, namespace string) bool {
	cluster = strings.TrimSpace(cluster)
	namespace = strings.TrimSpace(namespace)
	for _, rule := range t {
		if !verbAllowed(rule.Mode, verb) {
			continue
		}
		if !util.Match(rule.Cluster, cluster) {
			continue
		}
		if namespace == "" {
			if rule.ClusterScope {
				return true
			}
			continue
		}
		if rule.allowsNamespace(namespace) {
			return true
		}
	}
	return false
}

func (target Target) allowsNamespace(namespace string) bool {
	if target.Namespaces == nil {
		return true
	}
	for _, pattern := range target.Namespaces {
		if util.Match(pattern, namespace) {
			return true
		}
	}
	return false
}

type Proxy struct {
	Targets Targets
	mu      sync.RWMutex
	tokens  map[string]string
}

func New(targets Targets) *Proxy { return &Proxy{Targets: targets} }

type kubeconfigFile struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind"`
	Clusters       []namedCluster `yaml:"clusters"`
	Users          []namedUser    `yaml:"users"`
	Contexts       []namedContext `yaml:"contexts"`
	CurrentContext string         `yaml:"current-context"`
}

type namedCluster struct {
	Name    string        `yaml:"name"`
	Cluster clusterConfig `yaml:"cluster"`
}

type clusterConfig struct {
	Server                string `yaml:"server"`
	InsecureSkipTLSVerify bool   `yaml:"insecure-skip-tls-verify"`
}

type namedUser struct {
	Name string     `yaml:"name"`
	User userConfig `yaml:"user"`
}

type userConfig struct {
	Token string `yaml:"token"`
}

type namedContext struct {
	Name    string        `yaml:"name"`
	Context contextConfig `yaml:"context"`
}

type contextConfig struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace,omitempty"`
}

type kubeconfigContext struct {
	Name      string
	Namespace string
}

type kubeconfigState struct {
	Contexts       []kubeconfigContext
	CurrentContext string
}

func (p *Proxy) SyncConfig(ctx context.Context, host string, port int, dir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if port <= 0 {
		return fmt.Errorf("k8s: invalid proxy port")
	}
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}

	sourcePaths := clientcmd.NewDefaultClientConfigLoadingRules().GetLoadingPrecedence()
	if len(sourcePaths) == 0 {
		return fmt.Errorf("k8s: no kubeconfig paths")
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watch kubeconfig: %w", err)
	}
	defer watcher.Close()
	for _, sourcePath := range sourcePaths {
		dir := filepath.Dir(sourcePath)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("watch kubeconfig dir: %w", err)
		}
		if err := watcher.Add(dir); err != nil {
			return fmt.Errorf("watch kubeconfig dir: %w", err)
		}
	}

	lastKey, err := p.syncConfigOnce(host, port, dir, ^uint32(0))
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-watcher.Events:
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			matched := false
			for _, sourcePath := range sourcePaths {
				if filepath.Clean(event.Name) == filepath.Clean(sourcePath) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			var nextKey uint32
			nextKey, err = p.syncConfigOnce(host, port, dir, lastKey)
			if err != nil {
				return err
			}
			lastKey = nextKey
		case err := <-watcher.Errors:
			return err
		}
	}
}

func (p *Proxy) syncConfigOnce(host string, port int, dir string, lastKey uint32) (uint32, error) {
	source, err := readSourceKubeconfig()
	if err != nil {
		return lastKey, err
	}
	key := source.key()
	if key == lastKey {
		return lastKey, nil
	}

	inner, err := readInnerKubeconfig(filepath.Join(dir, ".kube", "config"))
	if err != nil {
		return lastKey, err
	}
	currentContext := source.CurrentContext
	if inner.CurrentContext != "" {
		currentContext = inner.CurrentContext
	}

	namespaces := make(map[string]string, len(inner.Contexts))
	for _, context := range inner.Contexts {
		if context.Namespace != "" {
			namespaces[context.Name] = context.Namespace
		}
	}
	for i := range source.Contexts {
		if namespace := namespaces[source.Contexts[i].Name]; namespace != "" {
			source.Contexts[i].Namespace = namespace
		}
	}

	content, tokens, err := renderKubeconfig(host, port, source.Contexts, currentContext)
	if err != nil {
		return lastKey, err
	}
	p.mu.Lock()
	p.tokens = tokens
	p.mu.Unlock()

	path := filepath.Join(dir, ".kube", "config")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return lastKey, fmt.Errorf("write kubeconfig: %w", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return lastKey, fmt.Errorf("write kubeconfig: %w", err)
	}
	slog.Info("synced k8s config", "path", path, "contexts", len(source.Contexts), "current_context", currentContext)
	return key, nil
}

func renderKubeconfig(host string, port int, contexts []kubeconfigContext, currentContext string) ([]byte, map[string]string, error) {
	tokens := make(map[string]string, len(contexts))
	config := kubeconfigFile{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters:   make([]namedCluster, 0, len(contexts)),
		Users:      make([]namedUser, 0, len(contexts)),
		Contexts:   make([]namedContext, 0, len(contexts)),
	}
	config.CurrentContext = currentContext
	for _, context := range contexts {
		token, err := randomToken()
		if err != nil {
			return nil, nil, fmt.Errorf("k8s: issue token for %q: %w", context.Name, err)
		}
		tokens[token] = context.Name
		config.Clusters = append(config.Clusters, namedCluster{
			Name: context.Name,
			Cluster: clusterConfig{
				Server:                fmt.Sprintf("https://%s:%d/%s", host, port, url.PathEscape(context.Name)),
				InsecureSkipTLSVerify: true,
			},
		})
		config.Users = append(config.Users, namedUser{
			Name: context.Name,
			User: userConfig{Token: token},
		})
		config.Contexts = append(config.Contexts, namedContext{
			Name: context.Name,
			Context: contextConfig{
				Cluster:   context.Name,
				User:      context.Name,
				Namespace: context.Namespace,
			},
		})
	}
	content, err := yaml.Marshal(config)
	if err != nil {
		return nil, nil, fmt.Errorf("k8s: marshal kubeconfig: %w", err)
	}
	return content, tokens, nil
}

func (s kubeconfigState) key() uint32 {
	hash := crc32.NewIEEE()
	for _, context := range s.Contexts {
		_, _ = hash.Write([]byte(context.Name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(context.Namespace))
		_, _ = hash.Write([]byte{0})
	}
	_, _ = hash.Write([]byte(s.CurrentContext))
	return hash.Sum32()
}

func verbAllowed(ruleVerb, requested Verb) bool {
	switch ruleVerb {
	case ReadWrite:
		return requested == Read || requested == ReadWrite
	case Read:
		return requested == Read
	default:
		return false
	}
}

func readSourceKubeconfig() (kubeconfigState, error) {
	config, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return kubeconfigState{}, nil
		}
		return kubeconfigState{}, err
	}

	contextNames := make([]string, 0, len(config.Contexts))
	for context := range config.Contexts {
		contextNames = append(contextNames, context)
	}
	sort.Strings(contextNames)

	contexts := make([]kubeconfigContext, 0, len(contextNames))
	for _, context := range contextNames {
		contextConfig := config.Contexts[context]
		namespace := ""
		if contextConfig != nil {
			namespace = contextConfig.Namespace
		}
		contexts = append(contexts, kubeconfigContext{Name: context, Namespace: namespace})
	}
	return newKubeconfigState(config.CurrentContext, contexts), nil
}

func readInnerKubeconfig(path string) (kubeconfigState, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return kubeconfigState{}, nil
		}
		return kubeconfigState{}, err
	}
	var config kubeconfigFile
	if err := yaml.Unmarshal(content, &config); err != nil {
		return kubeconfigState{}, err
	}
	contexts := make([]kubeconfigContext, 0, len(config.Contexts))
	for _, context := range config.Contexts {
		contexts = append(contexts, kubeconfigContext{
			Name:      context.Name,
			Namespace: context.Context.Namespace,
		})
	}
	return newKubeconfigState(config.CurrentContext, contexts), nil
}

func newKubeconfigState(currentContext string, contexts []kubeconfigContext) kubeconfigState {
	state := kubeconfigState{CurrentContext: strings.TrimSpace(currentContext)}
	seen := make(map[string]struct{}, len(contexts))
	for _, context := range contexts {
		context.Name = strings.TrimSpace(context.Name)
		context.Namespace = strings.TrimSpace(context.Namespace)
		if context.Name == "" {
			continue
		}
		if _, ok := seen[context.Name]; ok {
			continue
		}
		seen[context.Name] = struct{}{}
		state.Contexts = append(state.Contexts, context)
	}
	return state
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
