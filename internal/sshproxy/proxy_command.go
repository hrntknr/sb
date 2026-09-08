package sshproxy

import (
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func dialUpstreamProxyCommand(command, addr string, config *cryptossh.ClientConfig) (*cryptossh.Client, error) {
	conn, err := startProxyCommand(command, addr)
	if err != nil {
		return nil, err
	}
	clientConn, chans, reqs, err := cryptossh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return cryptossh.NewClient(clientConn, chans, reqs), nil
}

// startProxyCommand runs the ssh ProxyCommand and connects to it via stdio.
func startProxyCommand(command, addr string) (net.Conn, error) {
	cmd := exec.Command("/bin/sh", "-c", command)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &commandConn{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		addr:   addr,
		once:   sync.Once{},
		done:   make(chan struct{}),
	}, nil
}

type commandConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	addr   string
	once   sync.Once
	done   chan struct{}
}

func (c *commandConn) Read(b []byte) (int, error)  { return c.stdout.Read(b) }
func (c *commandConn) Write(b []byte) (int, error) { return c.stdin.Write(b) }

func (c *commandConn) Close() error {
	c.once.Do(func() {
		_ = c.stdin.Close()
		_ = c.stdout.Close()
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		go func() {
			_ = c.cmd.Wait()
			close(c.done)
		}()
	})
	select {
	case <-c.done:
	case <-time.After(time.Second):
	}
	return nil
}

func (c *commandConn) LocalAddr() net.Addr              { return commandAddr{c.addr} }
func (c *commandConn) RemoteAddr() net.Addr             { return commandAddr{c.addr} }
func (c *commandConn) SetDeadline(time.Time) error      { return nil }
func (c *commandConn) SetReadDeadline(time.Time) error  { return nil }
func (c *commandConn) SetWriteDeadline(time.Time) error { return nil }

type commandAddr struct{ addr string }

func (a commandAddr) Network() string { return "proxycommand" }
func (a commandAddr) String() string  { return a.addr }
