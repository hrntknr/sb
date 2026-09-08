package sshproxy

import (
	"net"
	"testing"

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
			go forwardChannel(upstream, ch, nil)
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
		forwardGlobalRequests(innerReqs, upstream, true)
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

// forwardGlobalRequests must reject downstream global requests when
// forwarding is not allowed.
func TestForwardGlobalRequestsRejectsWhenDisallowed(t *testing.T) {
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

	go forwardGlobalRequests(innerReqs, upstream, false)

	ok, _, err := downstream.SendRequest("ping", true, []byte("hello"))
	if err != nil || ok {
		t.Fatalf("SendRequest() = %v, %v; want rejected reply", ok, err)
	}
}
