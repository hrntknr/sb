package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// Serve accepts downstream connections. Each connection carries an SSH session
// whose exec payload names the real target ("proxy-ssh <user> <host> <port>");
// the inner SSH traffic on that session is policy-checked and forwarded to the
// upstream host.
func (p *Proxy) Serve(l net.Listener) error {
	config := &cryptossh.ServerConfig{PublicKeyCallback: p.authorizeIssuedKey}
	hostSigner, err := p.getOrCreateHostCASigner()
	if err != nil {
		return fmt.Errorf("ssh: host key: %w", err)
	}
	config.AddHostKey(hostSigner)

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		if !p.track(conn) {
			// Shutdown started: reject the connection outright.
			_ = conn.Close()
			continue
		}
		go p.serveOuterConn(conn, config)
	}
}

// track registers a downstream connection for Shutdown. It reports false once
// shutdown started: the connection is then closed by its acceptor.
func (p *Proxy) track(conn net.Conn) bool { return p.conns.track(conn) }

// untrack marks one connection's cleanup done.
func (p *Proxy) untrack(conn net.Conn) { p.conns.untrack(conn) }

func (p *Proxy) serveOuterConn(conn net.Conn, config *cryptossh.ServerConfig) {
	defer p.untrack(conn)
	server, chans, reqs, err := cryptossh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer server.Close()
	go cryptossh.DiscardRequests(reqs)

	// This connection's stop context: cancelled when the shutdown begins,
	// cutting what it starts upstream — the resolution, the dial and
	// handshake, the ProxyCommand child.
	ctx := p.stopContext()
	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(cryptossh.UnknownChannelType, "session required")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go p.serveOuterSession(ctx, channel, requests)
	}
}

func (p *Proxy) serveOuterSession(ctx context.Context, channel cryptossh.Channel, requests <-chan *cryptossh.Request) {
	defer channel.Close()
	for req := range requests {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}
		var payload struct {
			Command string
		}
		if err := cryptossh.Unmarshal(req.Payload, &payload); err != nil {
			req.Reply(false, nil)
			return
		}
		cfg, ok := p.resolveTarget(ctx, payload.Command)
		if !ok {
			slog.Warn("rejected ssh proxy command", "command", payload.Command)
			req.Reply(false, nil)
			return
		}
		slog.Info("proxying ssh connection", "requested_user", cfg.User, "host", cfg.Host, "port", cfg.Port)
		req.Reply(true, nil)
		p.serveInnerSSH(ctx, channel, cfg)
		return
	}
}

// SetTargets replaces the policy targets, called on config reloads.
func (p *Proxy) SetTargets(targets Targets) {
	p.mu.Lock()
	p.Targets = targets
	p.mu.Unlock()
}

// allowsTarget reports whether the current policy permits the resolved
// config's upstream connection.
func (p *Proxy) allowsTarget(cfg sshConfig) bool {
	p.mu.Lock()
	targets := p.Targets
	p.mu.Unlock()
	return targets.Allows(cfg.Host, cfg.User, atoiPort(cfg.Port))
}

// resolveTarget parses a "proxy-ssh <user> <host> <port>" exec payload,
// resolves the upstream ssh config, and checks that the policy permits the
// connection it describes.
func (p *Proxy) resolveTarget(ctx context.Context, command string) (cfg sshConfig, ok bool) {
	fields := strings.Fields(command)
	if len(fields) != 4 || fields[0] != "proxy-ssh" || fields[1] == "" || fields[2] == "" || !validPort(fields[3]) {
		return sshConfig{}, false
	}
	cfg, err := upstreamConfig(ctx, fields[1], fields[2], fields[3])
	if err != nil {
		return sshConfig{}, false
	}
	if !p.allowsTarget(cfg) {
		return sshConfig{}, false
	}
	return cfg, true
}

func validPort(port string) bool {
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n >= 1
}

// atoiPort parses the port string of a resolved config; the resolution
// yields only valid ports, so a failure is 0.
func atoiPort(port string) int {
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}

// serveInnerSSH terminates the inner SSH handshake on the outer session
// channel (presenting a host certificate for the requested host) and forwards
// channels to the upstream connection.
func (p *Proxy) serveInnerSSH(ctx context.Context, channel cryptossh.Channel, cfg sshConfig) {
	serverConfig, err := p.innerServerConfig(cfg.RequestedHost)
	if err != nil {
		return
	}
	server, chans, reqs, err := cryptossh.NewServerConn(channelConn{Channel: channel}, serverConfig)
	if err != nil {
		return
	}
	defer server.Close()

	upstream, err := dialUpstream(ctx, cfg, p.AgentSocket())
	if err != nil {
		slog.Error("failed to dial ssh upstream", "host", cfg.Host, "port", cfg.Port, "error", err)
		return
	}
	defer upstream.Close()

	// With access: full every request and channel the downstream client
	// sends is relayed: reverse forwarding too.
	go forwardGlobalRequests(reqs, upstream)
	go reverseForwardChannels(server, upstream)
	for ch := range chans {
		go serveInnerChannel(upstream, ch)
	}
}

func serveInnerChannel(upstream *cryptossh.Client, ch cryptossh.NewChannel) {
	forwardChannel(upstream, ch, nil)
}

// innerServerConfig signs a fresh host key with the proxy host CA for the
// requested host, so the downstream client verifies it via known_hosts.
func (p *Proxy) innerServerConfig(host string) (*cryptossh.ServerConfig, error) {
	ca, err := p.getOrCreateHostCASigner()
	if err != nil {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hostSigner, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	cert := &cryptossh.Certificate{
		Key:             hostSigner.PublicKey(),
		CertType:        cryptossh.HostCert,
		ValidPrincipals: hostCertPrincipals(host),
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(24 * time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	certSigner, err := cryptossh.NewCertSigner(cert, hostSigner)
	if err != nil {
		return nil, err
	}
	config := &cryptossh.ServerConfig{PublicKeyCallback: p.authorizeIssuedKey}
	config.AddHostKey(certSigner)
	return config, nil
}

func hostCertPrincipals(host string) []string {
	lowerHost := strings.ToLower(host)
	if lowerHost == host {
		return []string{host}
	}
	return []string{host, lowerHost}
}

func (p *Proxy) authorizeIssuedKey(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
	p.mu.Lock()
	issuedKey := p.issuedKey
	p.mu.Unlock()
	if issuedKey == "" || string(cryptossh.MarshalAuthorizedKey(key)) != issuedKey {
		return nil, fmt.Errorf("ssh: unauthorized key")
	}
	return nil, nil
}

type channelConn struct {
	cryptossh.Channel
}

func (c channelConn) LocalAddr() net.Addr              { return channelAddr("local") }
func (c channelConn) RemoteAddr() net.Addr             { return channelAddr("remote") }
func (c channelConn) SetDeadline(time.Time) error      { return nil }
func (c channelConn) SetReadDeadline(time.Time) error  { return nil }
func (c channelConn) SetWriteDeadline(time.Time) error { return nil }

type channelAddr string

func (a channelAddr) Network() string { return string(a) }
func (a channelAddr) String() string  { return string(a) }
