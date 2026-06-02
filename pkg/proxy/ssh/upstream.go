package ssh

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

type sshConfig struct {
	Host             string
	User             string
	Port             string
	IdentityFiles    []string
	CertificateFiles []string
	ProxyCommand     string
	IdentitiesOnly   bool
}

func dialUpstream(config sshConfig) (*cryptossh.Client, error) {
	auth, err := upstreamAuthMethods(config.IdentityFiles, config.CertificateFiles)
	if err != nil {
		return nil, config.wrapError(err)
	}
	clientConfig := &cryptossh.ClientConfig{
		User:            config.User,
		Auth:            auth,
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	if config.UsesProxyCommand() {
		slog.Debug("dialing ssh upstream with proxy command", "user", config.User, "host", config.Host, "port", config.Port)
		return config.wrapClient(dialUpstreamProxyCommand(config.ProxyCommand, config.Addr(), clientConfig))
	}
	slog.Debug("dialing ssh upstream", "user", config.User, "host", config.Host, "port", config.Port)
	return config.wrapClient(cryptossh.Dial("tcp", config.Addr(), clientConfig))
}

func (c sshConfig) Addr() string {
	return net.JoinHostPort(c.Host, c.Port)
}

func (c sshConfig) UsesProxyCommand() bool {
	return c.ProxyCommand != "" && !strings.EqualFold(c.ProxyCommand, "none")
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
