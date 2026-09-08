package sshproxy

import (
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
		go p.serveOuterConn(conn, config)
	}
}

func (p *Proxy) serveOuterConn(conn net.Conn, config *cryptossh.ServerConfig) {
	server, chans, reqs, err := cryptossh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
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
		go p.serveOuterSession(channel, requests)
	}
}

func (p *Proxy) serveOuterSession(channel cryptossh.Channel, requests <-chan *cryptossh.Request) {
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
		cfg, capability, ok := p.resolveTarget(payload.Command)
		if !ok {
			slog.Warn("rejected ssh proxy command", "command", payload.Command)
			req.Reply(false, nil)
			return
		}
		slog.Info("proxying ssh connection", "requested_user", cfg.User, "host", cfg.Host, "port", cfg.Port)
		req.Reply(true, nil)
		p.serveInnerSSH(channel, cfg, capability)
		return
	}
}

// SetTargets replaces the policy targets, called on config reloads.
func (p *Proxy) SetTargets(targets Targets) {
	p.mu.Lock()
	p.Targets = targets
	p.mu.Unlock()
}

// capability returns the current policy capability for host.
func (p *Proxy) capability(host string) Capability {
	p.mu.Lock()
	targets := p.Targets
	p.mu.Unlock()
	return targets.Capability(host)
}

// resolveTarget parses a "proxy-ssh <user> <host> <port>" exec payload,
// resolves the upstream ssh config, and checks that the host has a capability.
func (p *Proxy) resolveTarget(command string) (cfg sshConfig, capability Capability, ok bool) {
	fields := strings.Fields(command)
	if len(fields) != 4 || fields[0] != "proxy-ssh" || fields[1] == "" || fields[2] == "" || !validPort(fields[3]) {
		return sshConfig{}, Capability{}, false
	}
	cfg, err := upstreamConfig(fields[1], fields[2], fields[3])
	if err != nil {
		return sshConfig{}, Capability{}, false
	}
	capability = p.capability(cfg.Host)
	if capability.Empty() {
		return sshConfig{}, Capability{}, false
	}
	return cfg, capability, true
}

func validPort(port string) bool {
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n >= 1
}

// serveInnerSSH terminates the inner SSH handshake on the outer session
// channel (presenting a host certificate for the requested host) and forwards
// channels to the upstream connection.
func (p *Proxy) serveInnerSSH(channel cryptossh.Channel, cfg sshConfig, capability Capability) {
	serverConfig, err := p.innerServerConfig(cfg.RequestedHost)
	if err != nil {
		return
	}
	server, chans, reqs, err := cryptossh.NewServerConn(channelConn{Channel: channel}, serverConfig)
	if err != nil {
		return
	}
	defer server.Close()

	upstream, err := dialUpstream(cfg, p.AgentSocket())
	if err != nil {
		slog.Error("failed to dial ssh upstream", "host", cfg.Host, "port", cfg.Port, "error", err)
		return
	}
	defer upstream.Close()

	go forwardGlobalRequests(reqs, upstream, capability.Forward)
	if capability.Forward {
		// Reverse forwarding: channels the upstream opens in response to
		// forwarded-tcpip requests go back to the downstream client.
		go reverseForwardChannels(server, upstream)
	}

	for ch := range chans {
		go serveInnerChannel(upstream, capability, ch)
	}
}

func serveInnerChannel(upstream *cryptossh.Client, capability Capability, ch cryptossh.NewChannel) {
	if ch.ChannelType() != "session" {
		if !capability.Forward {
			ch.Reject(cryptossh.Prohibited, "forbidden")
			return
		}
		forwardChannel(upstream, ch, nil)
		return
	}
	forwardChannel(upstream, ch, func(req *cryptossh.Request) bool {
		switch req.Type {
		case "exec":
			if !capability.AllowsExec(execCommand(req)) {
				slog.Warn("rejected ssh exec by policy", "command", execCommand(req))
				return false
			}
			return true
		case "shell", "subsystem":
			return capability.Shell
		default:
			return true
		}
	})
}

func execCommand(req *cryptossh.Request) string {
	var payload struct{ Command string }
	_ = cryptossh.Unmarshal(req.Payload, &payload)
	return payload.Command
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
