package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

const testProxyPort = 12222

func TestCapabilityHostGlobs(t *testing.T) {
	targets := Targets{
		{Host: "github.com", Shell: true, Forward: true},
		{Host: "*.example.net", Shell: true, Forward: true},
	}

	tests := []struct {
		host string
		want bool
	}{
		{"github.com", true},
		{"GitHub.com", false},
		{"api.example.net", true},
		{"example.com", false},
	}

	for _, tt := range tests {
		if got := !targets.Capability(tt.host).Empty(); got != tt.want {
			t.Fatalf("Capability(%q) non-empty = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestCapabilityAllowsExec(t *testing.T) {
	targets := Targets{
		{Host: "github.com", Commands: []string{"*"}, Shell: true, Forward: true},
		{Host: "*", Commands: []string{"cat", "kubectl get"}},
	}

	tests := []struct {
		host    string
		command string
		want    bool
	}{
		{"github.com", "git-upload-pack 'repo.git'", true}, // "*" allows any command
		{"node.internal", "cat /etc/hosts", true},
		{"node.internal", "cat", true},
		{"node.internal", "cata /etc/hosts", false},    // first token must match exactly
		{"node.internal", "kubectl get pods", true},    // multi-token pattern
		{"node.internal", "kubectl delete pod", false}, // subcommand not allowed
		{"node.internal", "kubectl", false},            // too few tokens for pattern
		{"node.internal", "rm -rf /", false},
		{"node.internal", "cat a && cat b", true}, // every sub-command allowed
		{"node.internal", "cat a | kubectl get pods", true},
		{"node.internal", "cat a; rm -rf /", false}, // one sub-command denied
		{"node.internal", "cat a && kubectl delete x", false},
		{"node.internal", "cat $(rm -rf /)", false}, // command substitution evaluated
		{"node.internal", "cat `rm -rf /`", false},  // backtick substitution evaluated
		{"node.internal", "(cat a; rm b)", false},   // subshell evaluated
		{"node.internal", "cat 'a b'", true},        // quoting handled
		{"node.internal", "$CMD a", false},          // non-literal command name denied
		{"node.internal", "cat a > out", false},     // write redirection denied
		{"node.internal", "cat a >> out", false},    // append redirection denied
		{"node.internal", "cat < in", false},        // read redirection denied
		{"node.internal", "cat a && kubectl get pods", true},
		{"node.internal", "cat &&", false}, // parse error
		{"node.internal", "", false},
	}

	for _, tt := range tests {
		if got := targets.Capability(tt.host).AllowsExec(tt.command); got != tt.want {
			t.Fatalf("Capability(%q).AllowsExec(%q) = %v, want %v", tt.host, tt.command, got, tt.want)
		}
	}
}

func TestCapabilityShellAndForwardOnlyWhenUnrestricted(t *testing.T) {
	targets := Targets{
		{Host: "github.com", Shell: true, Forward: true},
		{Host: "*", Commands: []string{"cat"}},
	}

	if c := targets.Capability("github.com"); !c.Shell || !c.Forward {
		t.Fatalf("Capability(github.com) = %+v, want shell and forward", c)
	}
	if c := targets.Capability("node.internal"); c.Shell || c.Forward {
		t.Fatalf("Capability(node.internal) = %+v, want no shell/forward", c)
	}
}

func TestEmptyTargetsDenyAll(t *testing.T) {
	var targets Targets
	if c := targets.Capability("github.com"); !c.Empty() {
		t.Fatalf("empty targets produced capability: %+v", c)
	}
}

func TestHostCertPrincipalsIncludesLowercaseAlias(t *testing.T) {
	principals := hostCertPrincipals("Arc-i-0dbbd72eaec1aea61")
	if len(principals) != 2 || principals[0] != "Arc-i-0dbbd72eaec1aea61" || principals[1] != "arc-i-0dbbd72eaec1aea61" {
		t.Fatalf("hostCertPrincipals() = %#v", principals)
	}
}

func TestIssueInternalReturnsDirectProxyConfigAndKey(t *testing.T) {
	config, key, knownHosts, err := New(Targets{{Host: "github.com"}, {Host: "*.example.net"}}).issue("proxy.local", testProxyPort)
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}

	configText := string(config)
	if !strings.Contains(configText, "Host * !"+proxyHostAlias) {
		t.Fatalf("config does not contain wildcard host: %q", configText)
	}
	if !strings.Contains(configText, "Host "+proxyHostAlias) || !strings.Contains(configText, "HostName proxy.local") {
		t.Fatalf("config does not contain proxy host alias: %q", configText)
	}
	if !strings.Contains(configText, "ProxyCommand ssh "+proxyHostAlias+" proxy-ssh %r %n %p") {
		t.Fatalf("config does not contain proxy command: %q", configText)
	}
	if strings.Contains(configText, "StrictHostKeyChecking no") || strings.Contains(configText, "UserKnownHostsFile /dev/null") {
		t.Fatalf("config disables proxy host key checking: %q", configText)
	}
	if !strings.Contains(configText, "Port 12222") {
		t.Fatalf("config does not contain proxy port: %q", configText)
	}
	if !strings.Contains(configText, "UserKnownHostsFile ~/.ssh/known_hosts") {
		t.Fatalf("config = %q", configText)
	}
	if !strings.Contains(configText, "\n\tUser "+defaultUserMarker+"\n") {
		t.Fatalf("config does not contain default user marker: %q", configText)
	}
	if !strings.Contains(configText, "\n\tPort "+defaultPortMarker+"\n") {
		t.Fatalf("config does not contain default port marker: %q", configText)
	}

	keyText := string(key)
	if !strings.Contains(keyText, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("key = %q", keyText)
	}
	if _, err := cryptossh.ParseRawPrivateKey([]byte(keyText)); err != nil {
		t.Fatalf("private key is not parseable by ssh: %v", err)
	}

	knownHostsText := string(knownHosts)
	if !strings.Contains(knownHostsText, "@cert-authority * ssh-ed25519 ") {
		t.Fatalf("known_hosts = %q", knownHostsText)
	}
	if !strings.Contains(knownHostsText, "[proxy.local]:12222 ssh-ed25519 ") {
		t.Fatalf("known_hosts does not contain proxy host key: %q", knownHostsText)
	}
}

func TestIssueInternalRemembersIssuedPublicKey(t *testing.T) {
	proxy := &Proxy{}
	_, key, _, err := proxy.issue("proxy.local", testProxyPort)
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}

	rawKey, err := cryptossh.ParseRawPrivateKey(key)
	if err != nil {
		t.Fatalf("ParseRawPrivateKey() error = %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(rawKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	authorizedKey := string(cryptossh.MarshalAuthorizedKey(signer.PublicKey()))

	proxy.mu.Lock()
	got := proxy.issuedKey
	proxy.mu.Unlock()
	if got != authorizedKey {
		t.Fatalf("issued public key = %q, want %q", got, authorizedKey)
	}
}

func TestIssueInternalDefaultsToAllHostsWhenTargetsAreEmpty(t *testing.T) {
	config, _, knownHosts, err := (&Proxy{}).issue("proxy.local", testProxyPort)
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}

	configText := string(config)
	if !strings.Contains(configText, "Host *") {
		t.Fatalf("config = %q", configText)
	}
	knownHostsText := string(knownHosts)
	if !strings.Contains(knownHostsText, "@cert-authority * ") {
		t.Fatalf("known_hosts = %q", knownHostsText)
	}
}

func TestCurrentUsernameReplacesDefaultMarker(t *testing.T) {
	current, err := user.Current()
	if err != nil || current.Username == "" {
		t.Skip("current user is unavailable")
	}
	if got := currentUsername(defaultUserMarker); got != current.Username {
		t.Fatalf("currentUsername(default marker) = %q, want %q", got, current.Username)
	}
}

func TestParseSSHConfig(t *testing.T) {
	config := parseSSHConfig([]byte("user alice\nhostname bastion.example\nport 2222\nidentityfile ~/.ssh/id_ed25519\nidentityfile none\ncertificatefile ~/.ssh/id_ed25519-cert.pub\ncertificatefile none\nproxycommand /usr/bin/nc bastion.example 22\nidentitiesonly yes\n"))
	if config.User != "alice" || config.Host != "bastion.example" || config.Port != "2222" {
		t.Fatalf("parseSSHConfig() = %#v", config)
	}
	if len(config.IdentityFiles) != 1 || config.IdentityFiles[0] != "~/.ssh/id_ed25519" {
		t.Fatalf("identity files = %#v", config.IdentityFiles)
	}
	if len(config.CertificateFiles) != 1 || config.CertificateFiles[0] != "~/.ssh/id_ed25519-cert.pub" {
		t.Fatalf("certificate files = %#v", config.CertificateFiles)
	}
	if config.ProxyCommand != "/usr/bin/nc bastion.example 22" {
		t.Fatalf("proxy command = %q", config.ProxyCommand)
	}
	if !config.IdentitiesOnly {
		t.Fatalf("identities only = false, want true")
	}
}

func TestCertificateSignersPairsCertificateWithMatchingSigner(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	sshPublicKey, err := cryptossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}

	caPublicKey, caPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	caSigner, err := cryptossh.NewSignerFromKey(caPrivateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	caSSHPublicKey, err := cryptossh.NewPublicKey(caPublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}

	cert := &cryptossh.Certificate{
		Key:             sshPublicKey,
		CertType:        cryptossh.UserCert,
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		SignatureKey:    caSSHPublicKey,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "id_ed25519-cert.pub")
	if err := os.WriteFile(path, cryptossh.MarshalAuthorizedKey(cert), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if got := certificateSigners([]cryptossh.Signer{signer}, []string{path}); len(got) != 1 {
		t.Fatalf("certificateSigners() returned %d signers, want 1", len(got))
	}
}

func TestSyncConfigWritesSSHFiles(t *testing.T) {
	dir := t.TempDir()
	cancel := runSyncConfig(t, New(Targets{{Host: "github.com"}}), "proxy.local", dir)
	defer cancel()

	for _, name := range []string{".ssh/config", ".ssh/id_ed25519", ".ssh/known_hosts"} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		waitFor(t, func() bool {
			_, err := os.Stat(path)
			return err == nil
		})
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", name, info.Mode().Perm())
		}
	}
}

func TestSyncConfigEmptyDirWritesUnderWorkingDir(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore Chdir() error = %v", err)
		}
	}()

	cancel := runSyncConfig(t, &Proxy{}, "proxy.local", "")
	defer cancel()
	waitFor(t, func() bool {
		_, err := os.Stat(filepath.Join(dir, ".ssh", "config"))
		return err == nil
	})
	if _, err := os.Stat(filepath.Join(dir, ".ssh", "config")); err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
}

func runSyncConfig(t *testing.T, proxy *Proxy, host, dir string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- proxy.SyncConfig(ctx, host, testProxyPort, dir)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("SyncConfig() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatalf("SyncConfig() did not stop")
		}
	})
	return cancel
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition was not met")
}
