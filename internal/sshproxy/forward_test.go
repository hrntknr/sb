package sshproxy

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func testClientConfig(t *testing.T) *cryptossh.ClientConfig {
	t.Helper()
	return &cryptossh.ClientConfig{
		User:            "test",
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(testSigner(t))},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
	}
}

func testServerConfig(t *testing.T) *cryptossh.ServerConfig {
	t.Helper()
	config := &cryptossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(testSigner(t))
	return config
}

// startUpstream starts an ssh server that replies to global "ping" requests
// with ok and the given payload.
func startUpstream(t *testing.T, payload []byte) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				server, _, reqs, err := cryptossh.NewServerConn(conn, testServerConfig(t))
				if err != nil {
					conn.Close()
					return
				}
				defer server.Close()
				for req := range reqs {
					if req.WantReply {
						req.Reply(req.Type == "ping", payload)
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// startSessionUpstream starts an ssh server whose session channels echo
// "ok", send "exit-status 0", and close, like sshd after a successful
// command.
func startSessionUpstream(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { listener.Close() })
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
				go cryptossh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						ch.Reject(cryptossh.UnknownChannelType, "session required")
						continue
					}
					channel, requests, err := ch.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for req := range requests {
							if req.Type != "exec" {
								if req.WantReply {
									req.Reply(false, nil)
								}
								continue
							}
							req.Reply(true, nil)
							_, _ = channel.Write([]byte("ok"))
							_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{0}))
							_ = channel.CloseWrite()
							return
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// startStderrSessionUpstream starts an ssh server whose session channels
// write "stderr-data" as extended data (stderr) next to the main stream,
// send "exit-status 0", and close, like sshd after a command that wrote to
// stderr.
func startStderrSessionUpstream(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { listener.Close() })
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
				go cryptossh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						ch.Reject(cryptossh.UnknownChannelType, "session required")
						continue
					}
					channel, requests, err := ch.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for req := range requests {
							if req.Type != "exec" {
								if req.WantReply {
									req.Reply(false, nil)
								}
								continue
							}
							req.Reply(true, nil)
							_, _ = channel.Write([]byte("ok"))
							_, _ = channel.Stderr().Write([]byte("stderr-data"))
							_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{0}))
							_ = channel.CloseWrite()
							return
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// startChannelInner starts a downstream ssh server that hands accepted
// channels to the handler, like the proxy's inner layer does.
func startChannelInner(t *testing.T, handle func(cryptossh.NewChannel)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { listener.Close() })
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
				go cryptossh.DiscardRequests(reqs)
				for ch := range chans {
					handle(ch)
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// forwardChannel must deliver the upstream exit-status request before the
// downstream channel closes, or clients report the session as failed (ssh
// exits 255; ansible marks hosts unreachable). Regression test: pipe used to
// close the downstream channel while the exit-status request was still in
// flight.
func TestForwardChannelDeliversExitStatus(t *testing.T) {
	upstream, err := cryptossh.Dial("tcp", startSessionUpstream(t), testClientConfig(t))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer upstream.Close()

	newChannels := make(chan cryptossh.NewChannel)
	innerAddr := startChannelInner(t, func(ch cryptossh.NewChannel) { newChannels <- ch })
	go func() {
		for ch := range newChannels {
			go forwardChannel(upstream, ch)
		}
	}()

	downstream, err := cryptossh.Dial("tcp", innerAddr, testClientConfig(t))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer downstream.Close()

	const iterations = 20
	for i := 0; i < iterations; i++ {
		session, err := downstream.NewSession()
		if err != nil {
			t.Fatalf("iteration %d: NewSession() error = %v", i, err)
		}
		if err := session.Start("true"); err != nil {
			t.Fatalf("iteration %d: Start() error = %v (%T); exit status was not delivered before close", i, err, err)
		}
		if err := session.Wait(); err != nil {
			t.Fatalf("iteration %d: Wait() error = %v (%T); exit status was not delivered before close", i, err, err)
		}
		session.Close()
	}
}

// forwardChannel must deliver the upstream stderr (extended data) next to
// the main stream, or remote command error output is lost. Regression: pipe
// used to copy only the main stream.
func TestForwardChannelDeliversStderr(t *testing.T) {
	upstream, err := cryptossh.Dial("tcp", startStderrSessionUpstream(t), testClientConfig(t))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer upstream.Close()

	newChannels := make(chan cryptossh.NewChannel)
	innerAddr := startChannelInner(t, func(ch cryptossh.NewChannel) { newChannels <- ch })
	go func() {
		for ch := range newChannels {
			go forwardChannel(upstream, ch)
		}
	}()

	downstream, err := cryptossh.Dial("tcp", innerAddr, testClientConfig(t))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer downstream.Close()

	session, err := downstream.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	stderr := &syncBuffer{}
	session.Stderr = stderr
	if err := session.Start("true"); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	// Session.Stderr is filled by a goroutine that copies from the
	// channel and may lag behind Wait; wait for the stderr to arrive.
	deadline := time.Now().Add(5 * time.Second)
	for stderr.String() == "" {
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := stderr.String(); got != "stderr-data" {
		t.Fatalf("session.Stderr = %q, want %q", got, "stderr-data")
	}
}

// syncBuffer is a goroutine-safe bytes.Buffer for session writers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startInner starts a downstream ssh server like the proxy's inner layer and
// returns its address. The downstream client's global requests arrive on
// the returned channel; relaying them to an upstream client is the caller's
// job (that is what forwardGlobalRequests does in the proxy).
func startInner(t *testing.T) (string, <-chan *cryptossh.Request) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	reqs := make(chan *cryptossh.Request)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				server, _, global, err := cryptossh.NewServerConn(conn, testServerConfig(t))
				if err != nil {
					conn.Close()
					return
				}
				defer server.Close()
				for req := range global {
					reqs <- req
				}
			}()
		}
	}()
	return listener.Addr().String(), reqs
}

// forwardGlobalRequests must relay a downstream global request to the
// upstream and carry the reply payload (e.g. the port bound for
// tcpip-forward) back to the downstream client.
func TestForwardGlobalRequestsRelaysPayload(t *testing.T) {
	addr := startUpstream(t, []byte("bound-port"))
	upstream, err := cryptossh.Dial("tcp", addr, testClientConfig(t))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer upstream.Close()

	innerAddr, innerReqs := startInner(t)
	downstream, err := cryptossh.Dial("tcp", innerAddr, testClientConfig(t))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer downstream.Close()

	done := make(chan struct{})
	go func() {
		forwardGlobalRequests(innerReqs, upstream)
		close(done)
	}()

	ok, payload, err := downstream.SendRequest("ping", true, []byte("hello"))
	if err != nil || !ok {
		t.Fatalf("SendRequest() = %v, %v, %v; want ok reply", ok, payload, err)
	}
	if string(payload) != "bound-port" {
		t.Fatalf("reply payload = %q, want %q", payload, "bound-port")
	}
}
