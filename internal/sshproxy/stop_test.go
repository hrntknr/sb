package sshproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/skeema/knownhosts"
	cryptossh "golang.org/x/crypto/ssh"
)

// TestBeginStopCutsTheOpenConnections covers the stop's beginning: the set
// is closed — nothing may join it anymore — and every connection open at
// the stop is closed with it: no transfer on it keeps operating after
// the stop. Its cleanup never finishing — a transfer that never goes
// idle — is what Shutdown waits for, cut at its deadline.
func TestBeginStopCutsTheOpenConnections(t *testing.T) {
	proxy := New(nil, nil)
	server, client := net.Pipe()
	if !proxy.track(server) {
		t.Fatal("track rejected the connection")
	}

	// The deadline turns a connection that was not closed into a read
	// timeout: a blocking Read here would hang the test otherwise.
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	// The stop begins: the connection open at it is closed here.
	proxy.BeginStop()
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the connection was not closed by BeginStop: %v", err)
	}

	// The set is closed: nothing may join it anymore.
	late, latePeer := net.Pipe()
	defer latePeer.Close()
	if proxy.track(late) {
		t.Fatal("track accepted a connection after the stop began")
	}

	// Shutdown waits for the connection's cleanup: nothing untracks it,
	// so it returns at the deadline, not later.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	proxy.Shutdown(ctx)
	waited := time.Since(start)
	if waited < 150*time.Millisecond {
		t.Fatalf("Shutdown returned after %v; want it to wait out the deadline", waited)
	}
	if waited > 2*time.Second {
		t.Fatalf("Shutdown waited %v; want it cut at the deadline", waited)
	}
}

// TestShutdownCutsStuckUpstreamHandshake covers the upstream that never
// completes its handshake: the stop start (the stop context cancelled) cuts
// the dial and handshake at the deadline, closing the connection. Without
// it, a server that accepts but never sends its banner would hold the
// stop flow forever.
func TestShutdownCutsStuckUpstreamHandshake(t *testing.T) {
	// A server that accepts but never sends its SSH banner: the client's
	// handshake waits for it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn // held open, never writing
	}()
	addr := ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = dialUpstreamTCP(ctx, addr, &cryptossh.ClientConfig{})
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("dial waited %v; want it cut at the deadline", waited)
	}
	if err == nil {
		t.Fatal("the handshake completed; want it cut")
	}
	if conn := <-accepted; conn != nil {
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestStoppedProxyCommandCutsTheChild covers a ProxyCommand child that does
// not stop: the stop start (the stop context cancelled) kills it — the child
// is gone within the stop deadline, not waited for. The child publishes the
// shell's pid and its own (a `sleep` it started and waits for): both must
// die — the stop kills the whole process group, not just the shell that
// started it, or the shell's children outlive it holding the pipes.
func TestStoppedProxyCommandCutsTheChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := startProxyCommand(ctx, "echo $$; sleep 3600 & echo $!; wait", "target.example:22")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Both pids on the wire: the shell's, then the child it waits for.
	lines := bufio.NewReader(conn)
	shellPid, childPid := 0, 0
	for i := 0; i < 2; i++ {
		line, err := lines.ReadString('\n')
		if err != nil {
			t.Fatalf("the child did not publish its pid: %v", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			t.Fatalf("the published pid %q is not a pid: %v", line, err)
		}
		if i == 0 {
			shellPid = pid
		} else {
			childPid = pid
		}
	}
	if shellPid == 0 || childPid == 0 || shellPid == childPid {
		t.Fatalf("pids: shell=%d child=%d; want two distinct", shellPid, childPid)
	}
	for _, pid := range []int{shellPid, childPid} {
		if proc, err := os.FindProcess(pid); err != nil || proc == nil {
			t.Skip("process lookup not available")
		} else if err := proc.Signal(syscall.Signal(0)); err != nil {
			t.Skip("the process already exited")
		}
	}
	// A failing test would leak the group; kill both best-effort at the
	// end so no orphan outlives the test either way.
	t.Cleanup(func() {
		_ = syscall.Kill(shellPid, syscall.SIGKILL)
		_ = syscall.Kill(childPid, syscall.SIGKILL)
	})

	// The stop start: the child's process group is killed by the
	// connection's owner.
	cancel()
	pidsGone := func() bool {
		for _, pid := range []int{shellPid, childPid} {
			if err := syscall.Kill(pid, syscall.Signal(0)); err == nil {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(2 * time.Second)
	for !pidsGone() {
		if time.Now().After(deadline) {
			t.Fatalf("the ProxyCommand child survived the stop: shell=%d child=%d", shellPid, childPid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestProxyCommandWatchEndsWithEachConnection covers the watch lifecycle
// over iterated connections: the proxy is not stopped while the
// connections iterate — each connection's watch ends with the
// connection itself, so iterating does not accumulate one watch per
// connection. Without the end, a long-running proxy accumulates a watch
// per connection it ever served.
func TestProxyCommandWatchEndsWithEachConnection(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		conn, err := startProxyCommand(context.Background(), "exit 0", "target.example:22")
		if err != nil {
			t.Fatal(err)
		}
		// The connection ends: Close reaps the child, done closes,
		// the watch ends with it.
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Every watch ended with its connection: none is left waiting
	// for the proxy's stop that never comes.
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("the watches accumulated: %d goroutines before the iteration, %d after", before, runtime.NumGoroutine())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestAgentWatchEndsWithEachAuth covers the agent watch over iterated
// auths: the proxy is not stopped while the auths iterate — each auth's
// watch ends with the auth's own call, so iterating does not accumulate
// one watch per auth.
func TestAgentWatchEndsWithEachAuth(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				// The key list request: read the frame, answer with
				// an empty identities list.
				var length [4]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				request := make([]byte, binary.BigEndian.Uint32(length[:]))
				if _, err := io.ReadFull(conn, request); err != nil {
					return
				}
				answer := []byte{12, 0, 0, 0, 0} // identities answer, count 0
				var answerLength [4]byte
				binary.BigEndian.PutUint32(answerLength[:], uint32(len(answer)))
				if _, err := conn.Write(append(answerLength[:], answer...)); err != nil {
					return
				}
			}(conn)
		}
	}()

	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		signers, conn := sshAgentSigners(context.Background(), listener.Addr().String())
		if len(signers) != 0 {
			t.Fatalf("signers = %v; want none", signers)
		}
		if conn == nil {
			t.Fatal("no connection returned for the auth")
		}
		conn.Close()
	}
	// Every watch ended with its auth: none is left waiting for the
	// proxy's stop that never comes.
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("the watches accumulated: %d goroutines before the iteration, %d after", before, runtime.NumGoroutine())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// startStallingAgent serves the agent protocol on a unix socket: the
// identities request is answered with one key, the sign request is never
// answered — the connection stays open, the client waits on it. signAsked
// fires when a sign request arrives; connClosed when the client side of a
// connection that asked closes.
func startStallingAgent(t *testing.T) (socketPath string, signAsked, connClosed <-chan struct{}) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	blob := testSigner(t).PublicKey().Marshal() // any real key: the blob is its public form
	signAskedC := make(chan struct{}, 1)
	connClosedC := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				sawSign := false
				for {
					var length [4]byte
					if _, err := io.ReadFull(conn, length[:]); err != nil {
						if sawSign {
							select {
							case connClosedC <- struct{}{}:
							default:
							}
						}
						return
					}
					request := make([]byte, binary.BigEndian.Uint32(length[:]))
					if _, err := io.ReadFull(conn, request); err != nil {
						if sawSign {
							select {
							case connClosedC <- struct{}{}:
							default:
							}
						}
						return
					}
					if len(request) == 0 {
						continue
					}
					switch request[0] {
					case 11: // identities request: answered with one key
						answer := make([]byte, 0, 9+len(blob))
						answer = append(answer, 12) // identities answer
						answer = binary.BigEndian.AppendUint32(answer, 1)
						answer = binary.BigEndian.AppendUint32(answer, uint32(len(blob)))
						answer = append(answer, blob...)
						answer = binary.BigEndian.AppendUint32(answer, 0) // empty comment
						var frame [4]byte
						binary.BigEndian.PutUint32(frame[:], uint32(len(answer)))
						if _, err := conn.Write(append(frame[:], answer...)); err != nil {
							return
						}
					case 13: // sign request: stalled — no answer, no close
						sawSign = true
						select {
						case signAskedC <- struct{}{}:
						default:
						}
					default:
						return
					}
				}
			}(conn)
		}
	}()
	return listener.Addr().String(), signAskedC, connClosedC
}

// startAuthServer starts an ssh server that accepts any public key: the
// client's key query is answered, its handshake reaches the signature
// wait. The address is returned.
func startAuthServer(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	hostKey := testSigner(t)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				config := &cryptossh.ServerConfig{
					PublicKeyCallback: func(conn cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
						return &cryptossh.Permissions{}, nil
					},
				}
				config.AddHostKey(hostKey)
				server, _, reqs, err := cryptossh.NewServerConn(conn, config)
				if err != nil {
					conn.Close()
					return
				}
				defer server.Close()
				go cryptossh.DiscardRequests(reqs)
			}(conn)
		}
	}()
	return listener.Addr().String()
}

// TestStoppedAgentCutsTheSignatureWait covers the agent connection's
// watch over the handshake that uses it: a fake agent that answers the
// key list but stalls on the signature request — the handshake waits on
// it — and a stop that begins then cuts the dial at the connection.
// The watch ending with the key list would leave the signature wait
// uncut: the dial would wait for an agent that never answers.
func TestStoppedAgentCutsTheSignatureWait(t *testing.T) {
	socketPath, signAsked, connClosed := startStallingAgent(t)
	serverAddr := startAuthServer(t)
	_, port, _ := net.SplitHostPort(serverAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan error, 1)
	go func() {
		_, err := dialUpstream(ctx, sshConfig{
			User:                  "test",
			Host:                  "127.0.0.1",
			Port:                  port,
			StrictHostKeyChecking: "no",
		}, socketPath)
		dialed <- err
	}()

	// The signature wait is in flight: the agent stalls on it.
	select {
	case <-signAsked:
	case <-time.After(10 * time.Second):
		t.Fatal("the handshake never reached the signature wait")
	}
	cancel()
	select {
	case err := <-dialed:
		if err == nil {
			t.Fatal("the dial succeeded through a stalling agent")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dial did not return after the stop began")
	}
	// The agent connection ended with the dial.
	select {
	case <-connClosed:
	case <-time.After(10 * time.Second):
		t.Fatal("the agent connection did not end")
	}
}

// TestStoppedAgentCutsTheSignatureWaitThroughAProxyCommand covers the
// same signature wait over the ProxyCommand path: the child carries the
// transport, the agent connection's watch cuts the wait — closing the
// child alone would not, the handshake waits on the agent, not on the
// child.
func TestStoppedAgentCutsTheSignatureWaitThroughAProxyCommand(t *testing.T) {
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("nc not available: no child can carry the transport")
	}
	socketPath, signAsked, connClosed := startStallingAgent(t)
	serverHost, serverPort, _ := net.SplitHostPort(startAuthServer(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan error, 1)
	go func() {
		_, err := dialUpstream(ctx, sshConfig{
			User: "test",
			Host: "127.0.0.1",
			Port: "22",
			// The child carries the transport to the server: nc,
			// connecting it, like ssh's ProxyCommand does.
			ProxyCommand:          fmt.Sprintf("nc %s %s", serverHost, serverPort),
			HostKeyAlias:          "target.example",
			StrictHostKeyChecking: "no",
		}, socketPath)
		dialed <- err
	}()

	// The signature wait is in flight: the agent stalls on it.
	select {
	case <-signAsked:
	case <-time.After(10 * time.Second):
		t.Fatal("the handshake never reached the signature wait")
	}
	cancel()
	select {
	case err := <-dialed:
		if err == nil {
			t.Fatal("the dial succeeded through a stalling agent")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dial did not return after the stop began")
	}
	// The agent connection ended with the dial.
	select {
	case <-connClosed:
	case <-time.After(10 * time.Second):
		t.Fatal("the agent connection did not end")
	}
}

// upstreamRecord is what the upstream observes of the proxy's forwarded
// traffic: every connection-level global request, every channel open, and
// every exec request on an accepted channel. What the counters say after
// BeginStop must not grow: nothing may reach the upstream after it.
type upstreamRecord struct {
	globalRequests atomic.Int32
	channelOpens   atomic.Int32
	execRequests   atomic.Int32
}

// startRecordingUpstream starts an ssh server that records what reaches
// it: the upstream of the proxy's forwarded traffic. It answers global
// requests (ok), accepts every channel, and runs every exec request:
// what it records answers the client, so a recorded reply means the
// recording happened before it.
func startRecordingUpstream(t *testing.T) (addr string, record *upstreamRecord) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	record = &upstreamRecord{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				server, chans, reqs, err := cryptossh.NewServerConn(conn, testServerConfig(t))
				if err != nil {
					conn.Close()
					return
				}
				defer server.Close()
				go func() {
					for req := range reqs {
						record.globalRequests.Add(1)
						if req.WantReply {
							req.Reply(req.Type == "ping", nil)
						}
					}
				}()
				for ch := range chans {
					record.channelOpens.Add(1)
					_, requests, err := ch.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range requests {
							if req.Type != "exec" {
								if req.WantReply {
									req.Reply(false, nil)
								}
								continue
							}
							record.execRequests.Add(1)
							req.Reply(true, nil)
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String(), record
}

// sessionStream is the inner ssh protocol's transport: the session
// channel's data streams — what the user's ssh client rides through
// ProxyCommand. The session channel's stdin carries the inner protocol
// to the proxy's inner layer, its stdout carries it back.
type sessionStream struct {
	read  io.Reader
	write io.WriteCloser
}

func (s sessionStream) Read(p []byte) (int, error)  { return s.read.Read(p) }
func (s sessionStream) Write(p []byte) (int, error) { return s.write.Write(p) }
func (s sessionStream) Close() error                { return s.write.Close() }

// channelDataConn adapts the session channel's data streams to a net.Conn
// for the inner client's handshake: the same transport the user's ssh
// client speaks through, with the channel's streams carrying it. The ssh
// library closes the transport from more than one of its own goroutines
// (the handshake's cut, the teardown) — the close is once, so the
// channel's own writers are not raced.
type channelDataConn struct {
	sessionStream
	closeOnce sync.Once
}

func (c *channelDataConn) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.write.Close() })
	return err
}

func (*channelDataConn) LocalAddr() net.Addr              { return channelAddr("local") }
func (*channelDataConn) RemoteAddr() net.Addr             { return channelAddr("remote") }
func (*channelDataConn) SetDeadline(time.Time) error      { return nil }
func (*channelDataConn) SetReadDeadline(time.Time) error  { return nil }
func (*channelDataConn) SetWriteDeadline(time.Time) error { return nil }

// TestBeginStopCutsTheAuthenticatedSessions covers the stop's reach with
// the real ssh structures: a downstream client authenticated against the
// proxy's issued key, its inner ssh session riding the outer session
// channel and relaying to the upstream, and everything the stop cuts. What
// the session started upstream — the resolution and dial its requests would
// start — is cancelled, the tracked connections are closed, and new
// downstream connections are rejected outright: after BeginStop, new
// operations on the authenticated session and new connections never reach
// the upstream.
func TestBeginStopCutsTheAuthenticatedSessions(t *testing.T) {
	// The identity for the upstream dial's auth offer: the resolution
	// names it, the dial offers it. A fake ssh — the same pattern as the
	// resolution tests — resolves the proxy-ssh target deterministically
	// to the recording upstream: no real ssh, no machine config, the
	// host key check off (the test's upstream server has no known key).
	keyPath := filepath.Join(t.TempDir(), "identity")
	_, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := cryptossh.MarshalPrivateKey(identityPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	upstreamAddr, record := startRecordingUpstream(t)
	_, upstreamPort, _ := net.SplitHostPort(upstreamAddr)
	fakeSSH(t, fmt.Sprintf("hostname 127.0.0.1\nuser test\nport %s\nidentityfile %s\nstricthostkeychecking no\n", upstreamPort, keyPath))

	// The proxy: the real outer path — Serve on a listener, the inner
	// layer over the session channels, the upstream dials — and the real
	// issuance (WriteConfig) so the downstream client authenticates with
	// the issued key against the proxy's own records.
	proxy := New(Targets{{Host: "127.0.0.1"}}, nil)
	issueDir := t.TempDir()
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxyListener.Close() })
	go func() { _ = proxy.Serve(proxyListener) }()
	if err := proxy.WriteConfig("127.0.0.1", proxyListener.Addr().(*net.TCPAddr).Port, issueDir); err != nil {
		t.Fatal(err)
	}

	// The downstream client: authenticated against the proxy's issued
	// key, verifying the proxy's host key via the written known_hosts.
	// The raw transport is held for the stop's own observable.
	keyBytes, err := os.ReadFile(filepath.Join(issueDir, ".ssh", "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	db, err := knownhosts.NewDB(filepath.Join(issueDir, ".ssh", "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn, _, _, err := cryptossh.NewClientConn(conn, proxyListener.Addr().String(), &cryptossh.ClientConfig{
		User:            "test",
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)},
		HostKeyCallback: db.HostKeyCallback(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("the downstream handshake: %v; want the issued key accepted", err)
	}
	defer clientConn.Close()
	client := cryptossh.NewClient(clientConn, nil, nil)

	// The authenticated session: the exec names the target, the proxy
	// resolves and dials the upstream, and the inner ssh protocol rides
	// the session channel's data streams.
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := session.SendRequest("exec", true, cryptossh.Marshal(struct{ Command string }{"proxy-ssh test 127.0.0.1 " + upstreamPort}))
	if err != nil || !ok {
		t.Fatalf("exec request: %v, %v; want the proxy to accept it", ok, err)
	}
	inner, _, global, err := cryptossh.NewClientConn(&channelDataConn{sessionStream: sessionStream{read: stdout, write: stdin}}, "upstream", &cryptossh.ClientConfig{
		User:            "test",
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	defer inner.Close()
	go cryptossh.DiscardRequests(global)

	// What the session relays reaches the upstream: a global request is
	// recorded and answered, a channel open is recorded and accepted, and
	// an exec on the inner channel rides it. The replies coming back
	// mean the recording happened before them.
	if ok, _, err := inner.SendRequest("ping", true, nil); err != nil || !ok {
		t.Fatalf("inner global request: %v, %v; want it relayed and answered", ok, err)
	}
	if got := record.globalRequests.Load(); got != 1 {
		t.Fatalf("upstream global requests = %d, want 1", got)
	}
	channel, _, err := inner.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("inner channel open: %v; want it relayed", err)
	}
	if got := record.channelOpens.Load(); got != 1 {
		t.Fatalf("upstream channel opens = %d, want 1", got)
	}
	if ok, err := channel.SendRequest("exec", true, cryptossh.Marshal(struct{ Command string }{"true"})); err != nil || !ok {
		t.Fatalf("inner channel exec: %v, %v; want it relayed and answered", ok, err)
	}
	if got := record.execRequests.Load(); got != 1 {
		t.Fatalf("upstream exec requests = %d, want 1", got)
	}

	// The stop begins. Everything the session started upstream is
	// cancelled, the tracked connections are closed, and new connections
	// are rejected outright.
	proxy.BeginStop()

	// The connection's death is observable on the raw transport: closed
	// with the tracked set. What returns is the transport going — EOF
	// when the close arrives first, the closed connection when the ssh
	// teardown beats it to it — the same read that would never end
	// without a deadline.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the connection was not closed by the stop: %v", err)
	}

	// New operations on the authenticated connection: a new global
	// request, a new channel, an exec on the existing inner channel,
	// and a new exec on a new session. Fired on the transport after its
	// death, they go nowhere — whatever still waits on the transport
	// dies with it — and nothing of them is processed after the stop.
	// What still waits for a reply never comes. Each is waited for its
	// end: what returns is the failure the dead transport gives, not a
	// hang.
	after := func(name string, op func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- op() }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%s after the stop: succeeded; want the transport's failure", name)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s after the stop: did not end", name)
		}
	}
	after("global request", func() error {
		_, _, err := inner.SendRequest("ping2", true, nil)
		return err
	})
	after("channel open", func() error {
		_, _, err := inner.OpenChannel("session2", nil)
		return err
	})
	after("exec on the existing inner channel", func() error {
		_, err := channel.SendRequest("exec", true, cryptossh.Marshal(struct{ Command string }{"true"}))
		return err
	})
	after("exec on a new session", func() error {
		s, err := client.NewSession()
		if err != nil {
			return err
		}
		_, err = s.SendRequest("exec", true, cryptossh.Marshal(struct{ Command string }{"proxy-ssh test 127.0.0.1 " + upstreamPort}))
		return err
	})

	// A new connection after the stop: rejected outright — it cannot
	// authenticate, so nothing of it reaches the upstream either.
	if late, err := cryptossh.Dial("tcp", proxyListener.Addr().String(), &cryptossh.ClientConfig{
		User:            "test",
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)},
		HostKeyCallback: db.HostKeyCallback(),
		Timeout:         10 * time.Second,
	}); err == nil {
		late.Close()
		t.Fatal("a new connection after the stop: authenticated; want it rejected outright")
	}

	// Nothing of what the session and the new connection tried after
	// the stop reached the upstream: the counters say what did — the
	// one exec that did arrive did so before it.
	if got := record.globalRequests.Load(); got != 1 {
		t.Fatalf("upstream global requests after the stop = %d, want 1 (nothing new reached it)", got)
	}
	if got := record.channelOpens.Load(); got != 1 {
		t.Fatalf("upstream channel opens after the stop = %d, want 1 (nothing new reached it)", got)
	}
	if got := record.execRequests.Load(); got != 1 {
		t.Fatalf("upstream exec requests after the stop = %d, want 1 (nothing new reached it)", got)
	}
}
