package k8sproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/hrntknr/secretbridge/internal/util"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/tools/clientcmd"
)

// Proxy maps issued downstream tokens to kubeconfig contexts and proxies
// requests to the upstream cluster of the resolved context.
type Proxy struct {
	Targets Targets
	// host is the address downstream clients use to reach the proxy; it is
	// written into the generated kubeconfig and covered by the TLS
	// certificate.
	host string

	mu      sync.RWMutex
	tokens  map[string]string
	cert    tls.Certificate
	certErr error
	certOne sync.Once
}

func New(targets Targets, host string) *Proxy { return &Proxy{Targets: targets, host: host} }

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
	Server                   string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
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

// SyncConfig keeps the proxy kubeconfig under dir in sync with the source
// kubeconfig. It writes the initial config, signals it once through ready,
// and then follows source changes. current-context and namespace overrides
// made inside the generated config are preserved across syncs.
func (p *Proxy) SyncConfig(ctx context.Context, port int, dir string, ready chan<- struct{}) error {
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
	// Register the watcher before the initial sync so a change landing
	// between them is still picked up.
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

	lastKey, err := p.syncConfigOnce(port, dir, ^uint32(0))
	if ready != nil {
		close(ready)
	}
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
			nextKey, err = p.syncConfigOnce(port, dir, lastKey)
			if err != nil {
				return err
			}
			lastKey = nextKey
		case err := <-watcher.Errors:
			return err
		}
	}
}

func (p *Proxy) syncConfigOnce(port int, dir string, lastKey uint32) (uint32, error) {
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

	content, tokens, err := p.renderKubeconfig(port, source.Contexts, currentContext)
	if err != nil {
		return lastKey, err
	}
	// Write the new file first; on failure the state stays consistent with
	// the file still on disk.
	if err := util.WriteFileAtomic(filepath.Join(dir, ".kube", "config"), 0o600, content); err != nil {
		return lastKey, fmt.Errorf("write kubeconfig: %w", err)
	}
	p.mu.Lock()
	p.tokens = tokens
	p.mu.Unlock()

	slog.Info("synced k8s config", "path", filepath.Join(dir, ".kube", "config"), "contexts", len(source.Contexts), "current_context", currentContext)
	return key, nil
}

// renderKubeconfig builds the proxy-only kubeconfig with one downstream
// token per context. Tokens of contexts that already exist are reused, so a
// source rewrite does not invalidate credentials clients are still using.
// The proxy's TLS certificate is embedded as the cluster trust anchor so
// downstream clients verify the connection.
func (p *Proxy) renderKubeconfig(port int, contexts []kubeconfigContext, currentContext string) ([]byte, map[string]string, error) {
	certificate, err := p.certificate()
	if err != nil {
		return nil, nil, err
	}
	caData := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Certificate[0],
	}))

	p.mu.RLock()
	oldTokens := p.tokens // token -> context
	p.mu.RUnlock()
	// Invert to context -> token so existing contexts keep their token.
	existing := make(map[string]string, len(oldTokens))
	for token, context := range oldTokens {
		existing[context] = token
	}
	tokens := make(map[string]string, len(contexts)) // token -> context

	config := kubeconfigFile{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters:   make([]namedCluster, 0, len(contexts)),
		Users:      make([]namedUser, 0, len(contexts)),
		Contexts:   make([]namedContext, 0, len(contexts)),
	}
	config.CurrentContext = currentContext
	for _, context := range contexts {
		token, ok := existing[context.Name]
		if !ok {
			var err error
			token, err = randomToken()
			if err != nil {
				return nil, nil, fmt.Errorf("k8s: issue token for %q: %w", context.Name, err)
			}
		}
		tokens[token] = context.Name
		config.Clusters = append(config.Clusters, namedCluster{
			Name: context.Name,
			Cluster: clusterConfig{
				Server:                   fmt.Sprintf("https://%s/%s", net.JoinHostPort(p.host, strconv.Itoa(port)), url.PathEscape(context.Name)),
				CertificateAuthorityData: caData,
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

// readSourceKubeconfig loads context names, namespaces, and the current
// context from the user's kubeconfig.
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
		namespace := ""
		if contextConfig := config.Contexts[context]; contextConfig != nil {
			namespace = contextConfig.Namespace
		}
		contexts = append(contexts, kubeconfigContext{Name: context, Namespace: namespace})
	}
	return newKubeconfigState(config.CurrentContext, contexts), nil
}

// readInnerKubeconfig reads back the previously generated proxy kubeconfig to
// preserve user overrides of current-context and namespaces.
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
