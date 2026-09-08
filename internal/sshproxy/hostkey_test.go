package sshproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testSigner(t *testing.T) cryptossh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return signer
}

func writeKnownHosts(t *testing.T, entries ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestHostKeyCallbackInsecure(t *testing.T) {
	callback, err := hostKeyCallback(sshConfig{StrictHostKeyChecking: "no"})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := callback("example.com:22", testAddr{}, testSigner(t).PublicKey()); err != nil {
		t.Fatalf("insecure callback rejected key: %v", err)
	}
}

func TestHostKeyCallbackStrict(t *testing.T) {
	signer := testSigner(t)
	path := writeKnownHosts(t, knownhosts.Line([]string{"example.com:22"}, signer.PublicKey()))
	callback, err := hostKeyCallback(sshConfig{Host: "example.com", Port: "22", StrictHostKeyChecking: "yes", UserKnownHosts: []string{path}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}

	if err := callback("example.com:22", testAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("known host key rejected: %v", err)
	}
	if err := callback("example.com:22", testAddr{}, testSigner(t).PublicKey()); err == nil {
		t.Fatal("mismatched key accepted")
	}
	unknown, err := hostKeyCallback(sshConfig{Host: "unknown.example", Port: "22", StrictHostKeyChecking: "yes", UserKnownHosts: []string{path}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := unknown("ignored", testAddr{}, signer.PublicKey()); err == nil {
		t.Fatal("unknown host accepted in strict mode")
	}
}

func TestHostKeyCallbackStrictRejectsWithoutKnownHostsFiles(t *testing.T) {
	callback, err := hostKeyCallback(sshConfig{Host: "example.com", Port: "22", StrictHostKeyChecking: "yes", UserKnownHosts: []string{filepath.Join(t.TempDir(), "absent")}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := callback("example.com:22", testAddr{}, testSigner(t).PublicKey()); err == nil {
		t.Fatal("unknown host accepted without any known_hosts")
	}
}

func TestHostKeyCallbackPortNormalization(t *testing.T) {
	signer := testSigner(t)
	path := writeKnownHosts(t, knownhosts.Line([]string{"example.com:2222"}, signer.PublicKey()))
	callback, err := hostKeyCallback(sshConfig{Host: "example.com", Port: "2222", StrictHostKeyChecking: "yes", UserKnownHosts: []string{path}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}

	// The callback derives the match address from the resolved config.
	if err := callback("ignored", testAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("known host key with non-default port rejected: %v", err)
	}
	defaultPort, err := hostKeyCallback(sshConfig{Host: "example.com", Port: "22", StrictHostKeyChecking: "yes", UserKnownHosts: []string{path}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := defaultPort("ignored", testAddr{}, signer.PublicKey()); err == nil {
		t.Fatal("default-port form accepted a non-default-port entry")
	}
}

// accept-new trusts unknown keys on first use and records them, then rejects
// mismatches like strict mode.
func TestHostKeyCallbackAcceptNew(t *testing.T) {
	signer := testSigner(t)
	path := filepath.Join(t.TempDir(), "known_hosts") // does not exist yet
	callback, err := hostKeyCallback(sshConfig{Host: "example.com", Port: "22", StrictHostKeyChecking: "accept-new", UserKnownHosts: []string{path}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}

	if err := callback("example.com:22", testAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("unknown host key rejected in accept-new mode: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(content), "example.com ") {
		t.Fatalf("known_hosts did not record the accepted key: %q", content)
	}

	// A second connection re-reads known_hosts, so the recorded key is now
	// verified: the same key passes and a mismatched key is rejected.
	second, err := hostKeyCallback(sshConfig{Host: "example.com", Port: "22", StrictHostKeyChecking: "accept-new", UserKnownHosts: []string{path}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := second("example.com:22", testAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("recorded host key rejected: %v", err)
	}
	if err := second("example.com:22", testAddr{}, testSigner(t).PublicKey()); err == nil {
		t.Fatal("mismatched key accepted after recording")
	}
}

// The default "ask" cannot prompt here, so it behaves like non-interactive
// ssh: unknown hosts are rejected.
func TestHostKeyCallbackAskIsStrict(t *testing.T) {
	signer := testSigner(t)
	path := writeKnownHosts(t, knownhosts.Line([]string{"example.com:22"}, signer.PublicKey()))
	callback, err := hostKeyCallback(sshConfig{Host: "example.com", Port: "22", StrictHostKeyChecking: "ask", UserKnownHosts: []string{path}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}

	if err := callback("example.com:22", testAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("known host key rejected: %v", err)
	}
	unknown, err := hostKeyCallback(sshConfig{Host: "unknown.example", Port: "22", StrictHostKeyChecking: "ask", UserKnownHosts: []string{path}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := unknown("ignored", testAddr{}, signer.PublicKey()); err == nil {
		t.Fatal("unknown host accepted in ask mode")
	}
}

// Regression: like ssh, HostKeyAlias keys the known_hosts match by the alias
// instead of the resolved host name.
func TestHostKeyCallbackHonorsHostKeyAlias(t *testing.T) {
	signer := testSigner(t)
	path := writeKnownHosts(t, knownhosts.Line([]string{"bastion-alias"}, signer.PublicKey()))
	config := sshConfig{
		Host:                  "real.example.com",
		Port:                  "22",
		HostKeyAlias:          "bastion-alias",
		StrictHostKeyChecking: "yes",
		UserKnownHosts:        []string{path},
	}
	callback, err := hostKeyCallback(config)
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := callback("ignored", testAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("key recorded for the alias rejected: %v", err)
	}

	// An entry for the real host name alone must not satisfy the alias.
	realHost := writeKnownHosts(t, knownhosts.Line([]string{"real.example.com"}, signer.PublicKey()))
	config.UserKnownHosts = []string{realHost}
	callback, err = hostKeyCallback(config)
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := callback("ignored", testAddr{}, signer.PublicKey()); err == nil {
		t.Fatal("real host entry accepted for aliased match")
	}
}

// KnownHostsCommand is not supported and must fail closed even when strict
// checking is disabled, so an unsupported config is never silently ignored.
func TestHostKeyCallbackRejectsKnownHostsCommand(t *testing.T) {
	for _, mode := range []string{"yes", "no", "accept-new", ""} {
		config := sshConfig{Host: "example.com", Port: "22", KnownHostsCommand: "/usr/bin/fetch-keys", StrictHostKeyChecking: mode}
		if _, err := hostKeyCallback(config); err == nil {
			t.Fatalf("hostKeyCallback() with knownhostscommand and strict-host-key-checking=%q should fail", mode)
		}
	}
}

// accept-new must reject the connection when the key cannot be recorded.
func TestHostKeyCallbackAcceptNewRejectsWhenRecordingFails(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("regular file"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	callback, err := hostKeyCallback(sshConfig{
		Host:                  "example.com",
		Port:                  "22",
		StrictHostKeyChecking: "accept-new",
		UserKnownHosts:        []string{filepath.Join(parent, "known_hosts")},
	})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := callback("ignored", testAddr{}, testSigner(t).PublicKey()); err == nil {
		t.Fatal("unknown key accepted despite record failure")
	}
}

func TestHostKeyCallbackReadsGlobalKnownHosts(t *testing.T) {
	signer := testSigner(t)
	global := writeKnownHosts(t, knownhosts.Line([]string{"example.com:22"}, signer.PublicKey()))
	callback, err := hostKeyCallback(sshConfig{Host: "example.com", Port: "22", StrictHostKeyChecking: "yes", GlobalKnownHosts: []string{global}})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	if err := callback("example.com:22", testAddr{}, signer.PublicKey()); err != nil {
		t.Fatalf("key recorded in global known_hosts rejected: %v", err)
	}
}

func TestExistingKnownHostsFiles(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	// "none" and empty entries are filtered while parsing ssh -G output
	// (see TestParseSSHConfig); this operates on already-filtered lists.
	config := sshConfig{
		UserKnownHosts:   []string{existing, filepath.Join(dir, "absent"), "~/known_hosts"},
		GlobalKnownHosts: []string{filepath.Join(dir, "global-absent")},
	}
	files := existingKnownHostsFiles(config)
	if len(files) != 1 || files[0] != existing {
		t.Fatalf("existingKnownHostsFiles() = %v, want [%s]", files, existing)
	}
}

// Regression: a downstream process must not be able to make the proxy write
// through a symlink it installed in place of the .ssh directory.
func TestWriteConfigRejectsSymlinkedSSHDir(t *testing.T) {
	dir := t.TempDir()
	real := t.TempDir()
	if err := os.Symlink(real, filepath.Join(dir, ".ssh")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := New(nil, nil).WriteConfig("proxy.local", testProxyPort, dir); err == nil {
		t.Fatal("WriteConfig() through symlinked .ssh should fail")
	}
	if _, err := os.Stat(filepath.Join(real, "config")); !os.IsNotExist(err) {
		t.Fatal("write escaped through symlinked .ssh dir")
	}
}

func TestSSHAgentSignersReturnsConnection(t *testing.T) {
	// A unix socket that accepts connections but speaks no agent protocol:
	// Signers() fails, so the connection must be closed, not leaked.
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "agent.sock"))
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	signers, conn := sshAgentSigners(listener.Addr().String())
	if len(signers) != 0 {
		t.Fatalf("signers = %v, want none", signers)
	}
	if conn != nil {
		t.Fatal("connection returned despite Signers() failure")
	}
}

func TestSSHAgentSignersNoSocket(t *testing.T) {
	if signers, conn := sshAgentSigners(""); signers != nil || conn != nil {
		t.Fatalf("sshAgentSigners(\"\") = %v, %v; want nil, nil", signers, conn)
	}
}

type testAddr struct{}

func (testAddr) Network() string { return "tcp" }
func (testAddr) String() string  { return "127.0.0.1:22" }
