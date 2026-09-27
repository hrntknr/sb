package sshproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The proxy must fall back to the agent keys when the identity file keys are
// rejected by the upstream: x/crypto skips a failed auth method name, so one
// publickey method per signer source would never try the agent keys after
// the identity keys failed. Regression: upstreamAuthMethods used to build a
// separate publickey method per source.
func TestUpstreamAuthFallsBackToAgentKeys(t *testing.T) {
	// The upstream accepts only the agent key B; the identity file key A
	// (which sorts first within PublicKeys) is rejected.
	_, bPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	bSigner, err := cryptossh.NewSignerFromKey(bPrivate)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	acceptedKey := string(cryptossh.MarshalAuthorizedKey(bSigner.PublicKey()))

	socket := filepath.Join(t.TempDir(), "agent.sock")
	agentListener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = agentListener.Close() })
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: bPrivate, Comment: "test"}); err != nil {
		t.Fatalf("keyring.Add() error = %v", err)
	}
	go func() {
		for {
			conn, err := agentListener.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()

	_, aPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	aBlock, err := cryptossh.MarshalPrivateKey(aPrivate, "test key a")
	if err != nil {
		t.Fatalf("MarshalPrivateKey() error = %v", err)
	}
	aPath := filepath.Join(t.TempDir(), "id_test_a")
	if err := os.WriteFile(aPath, pem.EncodeToMemory(aBlock), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Upstream ssh server that accepts only the agent key.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				config := &cryptossh.ServerConfig{
					PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
						if string(cryptossh.MarshalAuthorizedKey(key)) != acceptedKey {
							return nil, fmt.Errorf("unacceptable key")
						}
						return nil, nil
					},
				}
				config.AddHostKey(testSigner(t))
				server, _, _, err := cryptossh.NewServerConn(conn, config)
				if err == nil {
					server.Close()
				}
			}()
		}
	}()

	port := strconv.Itoa(upstream.Addr().(*net.TCPAddr).Port)
	config := sshConfig{
		User:                  "test",
		Host:                  "127.0.0.1",
		Port:                  port,
		IdentityFiles:         []string{aPath},
		StrictHostKeyChecking: "no",
	}
	client, err := dialUpstream(config, socket)
	if err != nil {
		t.Fatalf("dialUpstream() error = %v (no fallback from the identity key to the agent key)", err)
	}
	_ = client.Close()
}
