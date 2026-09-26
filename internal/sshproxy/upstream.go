package sshproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"os/user"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// sshConfig is the resolved upstream connection settings for one target.
type sshConfig struct {
	Host                  string
	RequestedHost         string
	User                  string
	Port                  string
	IdentityFiles         []string
	CertificateFiles      []string
	ProxyCommand          string
	UserKnownHosts        []string
	GlobalKnownHosts      []string
	StrictHostKeyChecking string
	HostKeyAlias          string
	KnownHostsCommand     string
}

// matchAddr is the address host keys are matched and recorded by: the
// HostKeyAlias when set (like ssh), the resolved HostName otherwise.
func (c sshConfig) matchAddr() string {
	host := c.Host
	if c.HostKeyAlias != "" {
		host = c.HostKeyAlias
	}
	return net.JoinHostPort(host, c.Port)
}

// upstreamConfig resolves the effective ssh settings for a target by asking
// the local ssh client ("ssh -G"), which applies the user's ~/.ssh/config.
// The resolution is cut when ctx is (the shutdown began).
func upstreamConfig(ctx context.Context, username, host, port string) (sshConfig, error) {
	args := []string{"-G"}
	if username != "" && username != defaultUserMarker {
		args = append(args, "-l", username)
	}
	if port != "" && port != defaultPortMarker {
		args = append(args, "-p", port)
	}
	args = append(args, host)
	output, err := exec.CommandContext(ctx, "ssh", args...).Output()
	if err != nil {
		return sshConfig{}, err
	}

	config := parseSSHConfig(output)
	if config.Host == "" {
		config.Host = host
	}
	config.RequestedHost = host
	if config.User == "" || config.User == defaultUserMarker {
		config.User = currentUsername(config.User)
	}
	if username != "" && username != defaultUserMarker {
		config.User = username
	}
	if config.Port == "" {
		config.Port = "22"
	}
	if port != "" && port != defaultPortMarker {
		config.Port = port
	}
	slog.Debug("resolved ssh config", "user", config.User, "host", config.Host, "port", config.Port, "identity_files", len(config.IdentityFiles), "certificate_files", len(config.CertificateFiles), "proxy_command", config.ProxyCommand != "")
	return config, nil
}

func parseSSHConfig(output []byte) sshConfig {
	var config sshConfig
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "hostname":
			config.Host = value
		case "user":
			config.User = value
		case "port":
			config.Port = value
		case "identityfile":
			if value != "" && value != "none" {
				config.IdentityFiles = append(config.IdentityFiles, value)
			}
		case "certificatefile":
			if value != "" && value != "none" {
				config.CertificateFiles = append(config.CertificateFiles, value)
			}
		case "proxycommand":
			config.ProxyCommand = value
		case "userknownhostsfile":
			config.UserKnownHosts = appendKnownHostsFiles(config.UserKnownHosts, value)
		case "globalknownhostsfile":
			config.GlobalKnownHosts = appendKnownHostsFiles(config.GlobalKnownHosts, value)
		case "stricthostkeychecking":
			config.StrictHostKeyChecking = value
		case "hostkeyalias":
			if value != "" && value != "none" {
				config.HostKeyAlias = value
			}
		case "knownhostscommand":
			if value != "" && value != "none" {
				config.KnownHostsCommand = value
			}
		}
	}
	return config
}

func appendKnownHostsFiles(files []string, value string) []string {
	for _, file := range strings.Fields(value) {
		if file != "none" {
			files = append(files, file)
		}
	}
	return files
}

func currentUsername(fallback string) string {
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	return fallback
}

// dialUpstream connects to the upstream host, honoring a ProxyCommand if the
// user's ssh config requires one. agentSocketPath is resolved per call so
// restarted agents are followed. The connection — its resolution, the agent
// wait, the dial and handshake, the ProxyCommand child — is cut when ctx
// is (the shutdown began).
func dialUpstream(ctx context.Context, config sshConfig, agentSocketPath string) (*cryptossh.Client, error) {
	auth, agentConn, err := upstreamAuthMethods(ctx, config, agentSocketPath)
	if err != nil {
		return nil, config.wrapError(err)
	}
	if agentConn != nil {
		// The agent connection is only needed to sign during the
		// handshake.
		defer agentConn.Close()
	}
	clientConfig := &cryptossh.ClientConfig{
		User:    config.User,
		Auth:    auth,
		Timeout: 30 * time.Second,
	}
	if err := configureHostKey(config, clientConfig); err != nil {
		return nil, config.wrapError(err)
	}
	if config.ProxyCommand != "" && !strings.EqualFold(config.ProxyCommand, "none") {
		return config.wrapClient(dialUpstreamProxyCommand(ctx, config.ProxyCommand, config.matchAddr(), clientConfig))
	}
	return config.wrapClient(dialUpstreamTCP(ctx, config.Addr(), clientConfig))
}

// dialUpstreamTCP dials the host and runs the SSH handshake; a handshake
// that never completes is cut at ctx's deadline (the shutdown began).
func dialUpstreamTCP(ctx context.Context, addr string, config *cryptossh.ClientConfig) (*cryptossh.Client, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	type result struct {
		client *cryptossh.Client
		err    error
	}
	done := make(chan result, 1)
	go func() {
		clientConn, chans, reqs, err := cryptossh.NewClientConn(conn, addr, config)
		if err != nil {
			done <- result{err: err}
			return
		}
		done <- result{client: cryptossh.NewClient(clientConn, chans, reqs)}
	}()
	select {
	case r := <-done:
		return r.client, r.err
	case <-ctx.Done():
		// Closing the connection cuts the handshake; its goroutine's
		// cleanup is the connection owner's.
		conn.Close()
		r := <-done
		return nil, r.err
	}
}

func (c sshConfig) Addr() string {
	return net.JoinHostPort(c.Host, c.Port)
}

func (c sshConfig) wrapClient(client *cryptossh.Client, err error) (*cryptossh.Client, error) {
	if err != nil {
		return nil, c.wrapError(err)
	}
	return client, nil
}

func (c sshConfig) wrapError(err error) error {
	return fmt.Errorf("%s@%s:%s: %w", c.User, c.Host, c.Port, err)
}
