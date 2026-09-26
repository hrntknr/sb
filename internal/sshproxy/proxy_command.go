package sshproxy

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func dialUpstreamProxyCommand(ctx context.Context, command, addr string, config *cryptossh.ClientConfig) (*cryptossh.Client, error) {
	conn, err := startProxyCommand(ctx, command, addr)
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
// The child runs in its own process group; its whole group — the shell and
// everything it started — is killed when ctx is (the shutdown began).
func startProxyCommand(ctx context.Context, command, addr string) (net.Conn, error) {
	cmd := exec.Command("/bin/sh", "-c", command)
	// The process group is the shell's: the kill reaches the shell's
	// children too, not just the shell.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
	conn := &commandConn{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		addr:   addr,
		once:   sync.Once{},
		done:   make(chan struct{}),
	}
	// A shutdown that begins while the child runs kills it here: the
	// connection's owner reaps what it started. The watch ends with the
	// connection too — when the child is reaped, nothing is left to cut.
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-conn.done:
		}
	}()
	return conn, nil
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
			// The process group dies with the shell: children left
			// holding the pipes keep the caller's read open.
			_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
			go func() {
				_ = c.cmd.Wait()
				close(c.done)
			}()
		} else {
			close(c.done)
		}
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
