package k8sproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/hrntknr/sb/internal/util"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// Proxy maps issued downstream tokens to kubeconfig contexts and proxies
// requests to the upstream cluster of the resolved context.
type Proxy struct {
	Targets Targets
	// host is the address downstream clients use to reach the proxy; it is
	// written into the generated kubeconfig and covered by the TLS
	// certificate.
	host string
	// connections are the session's fixed upstream connections, resolved
	// per context name at startup; requests reuse them without reloading
	// the kubeconfig.
	connections map[string]*upstream

	mu      sync.RWMutex
	tokens  map[string]string
	cert    tls.Certificate
	certErr error
	certOne sync.Once
	server  *http.Server

	// stopCtx is cancelled when the shutdown begins: what the upstream
	// requests started is cut there. Requests issued after the shutdown
	// began inherit its cancellation.
	stopMu     sync.Mutex
	stopCtx    context.Context
	stopCancel context.CancelFunc
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

// SyncConfig issues the session's k8s credentials under dir once: it
// resolves the upstream connections from the source kubeconfig the
// initial read loads, renders the generated kubeconfig, and issues the
// downstream tokens — all fixed for the session. It signals the
// issuance's own result through ready (nil: the issuance succeeded),
// and then holds the session open until the run ends or the stop
// begins: a source change lands next session.
func (p *Proxy) SyncConfig(ctx context.Context, port int, dir string, ready chan<- error) error {
	// result reports the issuance's own outcome through ready, so the
	// start waiting on it learns about a failed setup: without it the
	// caller would wait forever for an issuance that never began.
	result := func(err error) error {
		if ready != nil {
			ready <- err
		}
		return err
	}
	if port <= 0 {
		return result(fmt.Errorf("k8s: invalid proxy port"))
	}
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	if err := p.startSession(port, dir); err != nil {
		return result(err)
	}
	if ready != nil {
		// The initial issuance's own result, not just its completion.
		ready <- nil
	}
	// The session is fixed: nothing follows the source, and nothing
	// reissues. Wait for the end — the run's (ctx) or the stop's,
	// whichever comes first.
	<-p.stopContext(ctx).Done()
	return nil
}

// startSession performs the session's initial issuance: it resolves the
// upstream connection for every context the policy names — fixing it
// for the session, the URL, TLS verification, and auth settings the
// context entry resolves to — and renders the initial generated
// kubeconfig from the same read. A context the policy names that does
// not resolve — one missing from the source kubeconfig — is a startup
// error.
func (p *Proxy) startSession(port int, dir string) error {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	raw, err := loadingRules.Load()
	if err != nil {
		return fmt.Errorf("load upstream kubeconfig: %w", err)
	}
	if err := p.resolveConnectionsFrom(raw, loadingRules); err != nil {
		return err
	}
	return p.renderAndWrite(port, dir, stateFromConfig(raw))
}

// renderAndWrite renders the generated kubeconfig for the state's
// contexts as far as the policy names them — only the permitted ones go
// into it — preserving the current-context and namespace overrides made
// inside it, writes it, and updates the tokens.
func (p *Proxy) renderAndWrite(port int, dir string, state kubeconfigState) error {
	p.mu.RLock()
	targets := p.Targets
	p.mu.RUnlock()
	// Only the contexts the policy names go into the generated
	// kubeconfig; the rules of one context never apply to another.
	allowed := make(map[string]bool)
	for _, context := range policyContexts(targets) {
		allowed[context] = true
	}
	contexts := make([]kubeconfigContext, 0, len(state.Contexts))
	for _, context := range state.Contexts {
		if !allowed[context.Name] {
			continue
		}
		contexts = append(contexts, context)
	}
	if currentContext := state.CurrentContext; !allowed[currentContext] && len(contexts) > 0 {
		// The source's current context is not permitted: fall back to
		// the first permitted one, so the generated kubeconfig stays
		// usable.
		state.CurrentContext = contexts[0].Name
	}

	inner, err := readInnerKubeconfig(filepath.Join(dir, ".kube", "config"))
	if err != nil {
		return err
	}
	if currentContext := inner.CurrentContext; currentContext != "" && allowed[currentContext] {
		state.CurrentContext = currentContext
	}

	namespaces := make(map[string]string, len(inner.Contexts))
	for _, context := range inner.Contexts {
		if context.Namespace != "" {
			namespaces[context.Name] = context.Namespace
		}
	}
	for i := range contexts {
		if namespace := namespaces[contexts[i].Name]; namespace != "" {
			contexts[i].Namespace = namespace
		}
	}

	content, tokens, err := p.renderKubeconfig(port, contexts, state.CurrentContext)
	if err != nil {
		return err
	}
	// Write the new file first; on failure the state stays consistent with
	// the file still on disk.
	if err := util.WriteFileAtomic(filepath.Join(dir, ".kube", "config"), 0o600, content); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	p.mu.Lock()
	p.tokens = tokens
	p.mu.Unlock()

	slog.Info("synced k8s config", "path", filepath.Join(dir, ".kube", "config"), "contexts", len(contexts), "current_context", state.CurrentContext)
	return nil
}

// renderKubeconfig builds the proxy-only kubeconfig with one downstream
// token per context. The proxy's TLS certificate is embedded as the
// cluster trust anchor so downstream clients verify the connection.
func (p *Proxy) renderKubeconfig(port int, contexts []kubeconfigContext, currentContext string) ([]byte, map[string]string, error) {
	certificate, err := p.certificate()
	if err != nil {
		return nil, nil, err
	}
	caData := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Certificate[0],
	}))

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
		token, err := randomToken()
		if err != nil {
			return nil, nil, fmt.Errorf("k8s: issue token for %q: %w", context.Name, err)
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

// stateFromConfig derives the source state — context names with their
// namespaces, and the current context — from a loaded source kubeconfig.
func stateFromConfig(config *api.Config) kubeconfigState {
	contextNames := make([]string, 0, len(config.Contexts))
	for context := range config.Contexts {
		contextNames = append(contextNames, context)
	}
	sort.Strings(contextNames)

	contexts := make([]kubeconfigContext, 0, len(contextNames))
	for _, context := range contextNames {
		namespace := ""
		if entry := config.Contexts[context]; entry != nil {
			namespace = entry.Namespace
		}
		contexts = append(contexts, kubeconfigContext{Name: context, Namespace: namespace})
	}
	return newKubeconfigState(config.CurrentContext, contexts)
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
