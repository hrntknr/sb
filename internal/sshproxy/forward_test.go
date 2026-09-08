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
