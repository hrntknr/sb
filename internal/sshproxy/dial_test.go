package sshproxy

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// TestStdioSSHServerChild is the ProxyCommand the dial tests below run:
// it serves an SSH server on its stdin/stdout until the parent kills it.
// It only serves in this mode when SB_TEST_STDIO_SERVER is set, so the
// test no-ops when the suite itself runs it.
func TestStdioSSHServerChild(t *testing.T) {
	if os.Getenv("SB_TEST_STDIO_SERVER") == "" {
		return
	}
	config := &cryptossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(testSigner(t))
	server, _, reqs, err := cryptossh.NewServerConn(stdioConn{}, config)
	if err != nil {
		return
	}
	defer server.Close()
	go func() {
		for req := range reqs {
			if req.WantReply {
				req.Reply(req.Type == "ping", []byte("pong"))
			}
		}
	}()
	select {} // serve until the parent kills the process
}

// stdioConn exposes the process stdin/stdout as the SSH server connection.
type stdioConn struct{}

func (stdioConn) Read(b []byte) (int, error)         { return os.Stdin.Read(b) }
func (stdioConn) Write(b []byte) (int, error)        { return os.Stdout.Write(b) }
func (stdioConn) Close() error                       { return nil }
func (stdioConn) LocalAddr() net.Addr                { return commandAddr{"stdio"} }
func (stdioConn) RemoteAddr() net.Addr               { return commandAddr{"stdio"} }
func (stdioConn) SetReadDeadline(t time.Time) error  { return os.Stdin.SetReadDeadline(t) }
func (stdioConn) SetWriteDeadline(t time.Time) error { return os.Stdout.SetWriteDeadline(t) }
func (stdioConn) SetDeadline(t time.Time) error {
	if err := os.Stdin.SetReadDeadline(t); err != nil {
		return err
	}
	return os.Stdout.SetWriteDeadline(t)
}

// A ProxyCommand that accepts the connection but never answers the
// handshake is dropped by the dial timeout instead of blocking forever.
func TestProxyCommandHandshakeTimeoutStalls(t *testing.T) {
	config := testClientConfig(t)
	config.Timeout = 300 * time.Millisecond
	start := time.Now()
	if _, err := dialUpstreamProxyCommand("sleep 10", "test", config); err == nil {
		t.Fatal("dialUpstreamProxyCommand() succeeded, want timeout error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dial took %v, want fast failure", elapsed)
	}
}

// After the handshake completes the deadline is cleared, so the
// connection keeps working past the dial timeout.
func TestProxyCommandHandshakeTimeoutCleared(t *testing.T) {
	command := fmt.Sprintf("SB_TEST_STDIO_SERVER=1 '%s' -test.run=TestStdioSSHServerChild", os.Args[0])
	config := testClientConfig(t)
	config.Timeout = 300 * time.Millisecond
	client, err := dialUpstreamProxyCommand(command, "test", config)
	if err != nil {
		t.Fatalf("dialUpstreamProxyCommand() error = %v", err)
	}
	defer client.Close()
	time.Sleep(2 * config.Timeout)
	ok, _, err := client.SendRequest("ping", true, nil)
	if err != nil || !ok {
		t.Fatalf("request after deadline: ok=%v err=%v", ok, err)
	}
}
