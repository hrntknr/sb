package ssh

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

func (p *Proxy) Serve(l net.Listener) error {
	if p == nil {
		return fmt.Errorf("ssh: nil Proxy")
	}
	if l == nil {
		return fmt.Errorf("ssh: nil listener")
	}

	config := &cryptossh.ServerConfig{PublicKeyCallback: p.authorizeIssuedKey}
	hostSigner, err := p.getOrCreateHostCASigner()
	if err != nil {
		return fmt.Errorf("ssh: host key: %w", err)
	}
	config.AddHostKey(hostSigner)

	for {
		conn, err := l.Accept()
		if err != nil {
			slog.Debug("ssh listener stopped", "error", err)
			return err
		}
		slog.Debug("accepted ssh proxy connection", "remote", conn.RemoteAddr().String())
		go p.serveOuterConn(conn, config)
	}
}

func (p *Proxy) serveOuterConn(conn net.Conn, config *cryptossh.ServerConfig) {
	server, chans, reqs, err := cryptossh.NewServerConn(conn, config)
	if err != nil {
		slog.Debug("rejected ssh proxy connection", "remote", conn.RemoteAddr().String(), "error", err)
		_ = conn.Close()
		return
	}
	defer server.Close()
	go cryptossh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			slog.Debug("rejected ssh channel", "type", ch.ChannelType())
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
		fields := strings.Fields(payload.Command)
		if len(fields) != 4 || fields[0] != "proxy-ssh" || fields[1] == "" || fields[2] == "" {
			slog.Warn("rejected ssh proxy command", "command", payload.Command)
			req.Reply(false, nil)
			return
		}
		user, host, port := fields[1], fields[2], fields[3]
		if _, err := strconv.Atoi(port); err != nil {
			slog.Warn("rejected ssh proxy command", "command", payload.Command, "host", host)
			req.Reply(false, nil)
			return
		}
		if len(p.Targets) > 0 && !p.Targets.Allows(host) {
			slog.Warn("rejected ssh proxy command", "command", payload.Command, "host", host)
			req.Reply(false, nil)
			return
		}
		slog.Info("proxying ssh connection", "requested_user", user, "host", host, "port", port)
		req.Reply(true, nil)
		p.serveInnerSSH(channel, user, host, port)
		return
	}
}

func (p *Proxy) serveInnerSSH(channel cryptossh.Channel, user, host, port string) {
	config, err := p.innerServerConfig(host)
	if err != nil {
		return
	}
	server, chans, reqs, err := cryptossh.NewServerConn(channelConn{Channel: channel}, config)
	if err != nil {
		return
	}
	defer server.Close()
	go cryptossh.DiscardRequests(reqs)

	upstream, err := dialUpstream(user, host, port)
	if err != nil {
		slog.Error("failed to dial ssh upstream", "requested_user", user, "host", host, "port", port, "error", err)
		return
	}
	defer upstream.Close()

	for ch := range chans {
		go forwardChannel(upstream, ch)
	}
}

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
