package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/hrntknr/sb/internal/util"
	cryptossh "golang.org/x/crypto/ssh"
)

const (
	proxyHostAlias    = "sb"
	defaultUserMarker = "__sb_default_user__"
	defaultPortMarker = "65535"
)

//go:embed templates/ssh_config.tmpl
var sshConfigTemplateText string

//go:embed templates/known_hosts.tmpl
var knownHostsTemplateText string

var (
	sshConfigTemplate  = template.Must(template.New("ssh_config").Parse(sshConfigTemplateText))
	knownHostsTemplate = template.Must(template.New("known_hosts").Parse(knownHostsTemplateText))
)

// Proxy authenticates issued downstream keys, enforces policy, and forwards
// sessions to upstream hosts.
type Proxy struct {
	Targets Targets
	// AgentSocket resolves the ssh-agent socket path for each upstream dial,
	// so restarted agents are followed.
	AgentSocket func() string

	mu           sync.Mutex
	issuedKey    string
	hostCASigner cryptossh.Signer

	// conns tracks open downstream connections for Shutdown.
	conns connSet

	// stopCtx is cancelled when the shutdown begins: what one connection
	// started (an upstream dial, a handshake, a ProxyCommand child) is
	// cut there.
	stopMu     sync.Mutex
	stopCtx    context.Context
	stopCancel context.CancelFunc
}

func New(targets Targets, agentSocket func() string) *Proxy {
	if agentSocket == nil {
		agentSocket = func() string { return os.Getenv("SSH_AUTH_SOCK") }
	}
	return &Proxy{Targets: targets, AgentSocket: agentSocket}
}

// stopContext returns the context that is cancelled when the shutdown
// begins. What it covers: the resolution (ssh -G), the dial and handshake,
// the ProxyCommand child — everything one connection starts upstream.
func (p *Proxy) stopContext() context.Context {
	p.stopMu.Lock()
	defer p.stopMu.Unlock()
	if p.stopCtx == nil {
		p.stopCtx, p.stopCancel = context.WithCancel(context.Background())
	}
	return p.stopCtx
}

// BeginStop starts the shutdown: everything the open connections started
// upstream — dials, handshakes, ProxyCommand children — is cancelled here,
// once, and the connections themselves are closed: no operation reaches
// the upstream after it — their cleanups follow.
func (p *Proxy) BeginStop() {
	p.stopContext()
	p.stopMu.Lock()
	cancel := p.stopCancel
	p.stopMu.Unlock()
	if cancel != nil {
		cancel()
	}
	p.conns.closeAll()
}

// WriteConfig issues downstream credentials and writes the ssh config, private
// key, and known_hosts under dir.
func (p *Proxy) WriteConfig(host string, port int, dir string) error {
	config, key, knownHosts, err := p.issue(host, port)
	if err != nil {
		return err
	}
	if err := util.WriteFileAtomic(filepath.Join(dir, ".ssh", "config"), 0o600, config); err != nil {
		return fmt.Errorf("write ssh config: %w", err)
	}
	if err := util.WriteFileAtomic(filepath.Join(dir, ".ssh", "id_ed25519"), 0o600, key); err != nil {
		return fmt.Errorf("write ssh private key: %w", err)
	}
	if err := util.WriteFileAtomic(filepath.Join(dir, ".ssh", "known_hosts"), 0o600, knownHosts); err != nil {
		return fmt.Errorf("write ssh known_hosts: %w", err)
	}
	slog.Info("wrote ssh config", "dir", dir, "host", host, "port", port)
	return nil
}

// issue generates the downstream key pair and renders the proxy config and
// known_hosts signed by the proxy host CA.
func (p *Proxy) issue(host string, port int) (config []byte, key []byte, knownHosts []byte, err error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, nil, nil, fmt.Errorf("ssh: empty proxy host")
	}
	if port <= 0 {
		return nil, nil, nil, fmt.Errorf("ssh: invalid proxy port")
	}

	privateKey, authorizedKey, err := issuePrivateKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssh: issue private key: %w", err)
	}
	p.mu.Lock()
	p.issuedKey = authorizedKey
	p.mu.Unlock()

	configText, err := renderTemplate(sshConfigTemplate, map[string]any{
		"DefaultUserMarker": defaultUserMarker,
		"DefaultPort":       defaultPortMarker,
		"ProxyHostAlias":    proxyHostAlias,
		"ProxyHost":         host,
		"ProxyPort":         port,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssh: render config: %w", err)
	}

	hostCASigner, err := p.getOrCreateHostCASigner()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssh: issue host ca: %w", err)
	}
	knownHostsText, err := renderTemplate(knownHostsTemplate, map[string]any{
		"HostCAPublic": strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(hostCASigner.PublicKey()))),
		"ProxyHost":    host,
		"ProxyPort":    port,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssh: render known_hosts: %w", err)
	}

	return []byte(configText), privateKey, []byte(knownHostsText), nil
}

func (p *Proxy) getOrCreateHostCASigner() (cryptossh.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hostCASigner != nil {
		return p.hostCASigner, nil
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	p.hostCASigner = signer
	return signer, nil
}

func renderTemplate(t *template.Template, data any) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func issuePrivateKey() ([]byte, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}

	block, err := cryptossh.MarshalPrivateKey(privateKey, "proxy key")
	if err != nil {
		return nil, "", err
	}

	sshPublicKey, err := cryptossh.NewPublicKey(publicKey)
	if err != nil {
		return nil, "", err
	}

	return pem.EncodeToMemory(block), string(cryptossh.MarshalAuthorizedKey(sshPublicKey)), nil
}
