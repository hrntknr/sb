package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/hrntknr/secretbridge/pkg/util"
	cryptossh "golang.org/x/crypto/ssh"
	"mvdan.cc/sh/v3/syntax"
)

const (
	proxyHostAlias    = "secretbridge"
	defaultUserMarker = "__secretbridge_default_user__"
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

type Target struct {
	Host     string
	Commands []string
	Shell    bool
	Forward  bool
}

type Targets []Target

type Capability struct {
	Commands []string
	Shell    bool
	Forward  bool
}

func (t Targets) Capability(host string) Capability {
	host = strings.TrimSpace(host)
	var c Capability
	for _, rule := range t {
		if !util.Match(rule.Host, host) {
			continue
		}
		c.Commands = append(c.Commands, rule.Commands...)
		c.Shell = c.Shell || rule.Shell
		c.Forward = c.Forward || rule.Forward
	}
	return c
}

func (c Capability) Empty() bool {
	return len(c.Commands) == 0 && !c.Shell && !c.Forward
}

func (c Capability) AllowsExec(command string) bool {
	for _, pattern := range c.Commands {
		if strings.TrimSpace(pattern) == "*" {
			return true
		}
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return false
	}
	seen, allowed := false, true
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Redirect:
			allowed = false // restricted hosts: pure command execution only
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				return true
			}
			seen = true
			if !c.allowsTokens(callTokens(n)) {
				allowed = false
			}
		}
		return true
	})
	return seen && allowed
}

func callTokens(call *syntax.CallExpr) []string {
	var tokens []string
	for _, w := range call.Args {
		lit, ok := wordLiteral(w)
		if !ok {
			break
		}
		tokens = append(tokens, lit)
	}
	return tokens
}

func wordLiteral(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func (c Capability) allowsTokens(tokens []string) bool {
	for _, pattern := range c.Commands {
		patternTokens := strings.Fields(pattern)
		if len(patternTokens) == 0 || len(tokens) < len(patternTokens) {
			continue
		}
		ok := true
		for i, pt := range patternTokens {
			if !util.Match(pt, tokens[i]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

type Proxy struct {
	Targets Targets

	mu           sync.Mutex
	issuedKey    string
	hostCASigner cryptossh.Signer
}

func New(targets Targets) *Proxy {
	return &Proxy{Targets: targets}
}

func (p *Proxy) SyncConfig(ctx context.Context, host string, port int, dir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	config, key, knownHosts, err := p.issue(host, port)
	if err != nil {
		return err
	}

	if err := writeFile(dir, ".ssh/config", 0o600, config); err != nil {
		return fmt.Errorf("write ssh config: %w", err)
	}
	if err := writeFile(dir, ".ssh/id_ed25519", 0o600, key); err != nil {
		return fmt.Errorf("write ssh private key: %w", err)
	}
	if err := writeFile(dir, ".ssh/known_hosts", 0o600, knownHosts); err != nil {
		return fmt.Errorf("write ssh known_hosts: %w", err)
	}
	slog.Info("synced ssh config", "dir", dir, "host", host, "port", port)

	<-ctx.Done()
	return nil
}

func (p *Proxy) issue(host string, port int) (config []byte, key []byte, knownHosts []byte, err error) {
	if p == nil {
		return nil, nil, nil, fmt.Errorf("ssh: nil Proxy")
	}
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

func writeFile(root, name string, mode fs.FileMode, content []byte) error {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, content, mode)
}
