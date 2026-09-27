package sshproxy

import (
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func dialUpstreamProxyCommand(command, addr string, config *cryptossh.ClientConfig) (*cryptossh.Client, error) {
	conn, err := startProxyCommand(command, addr)
	if err != nil {
		return nil, err
	}
	// Without a deadline, a ProxyCommand that accepts the connection
	// but never answers the handshake blocks the dial forever.
	if config.Timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	clientConn, chans, reqs, err := cryptossh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Connected: steady state has no time limit any more.
	_ = conn.SetDeadline(time.Time{})
	return cryptossh.NewClient(clientConn, chans, reqs), nil
}

// startProxyCommand runs the ssh ProxyCommand and connects to it via stdio.
// The child's pipe descriptors are passed to it directly, so reads and
// writes honor deadlines.
func startProxyCommand(command, addr string) (net.Conn, error) {
	cmd := exec.Command("/bin/sh", "-c", command)
	// The command may spawn children (ssh -W, nc); its own group lets
	// Close kill the whole tree instead of just the shell.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	childStdin, stdin, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdout, childStdout, err := os.Pipe()
	if err != nil {
		_ = childStdin.Close()
		_ = stdin.Close()
		return nil, err
	}
	cmd.Stdin = childStdin
	cmd.Stdout = childStdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = childStdin.Close()
		_ = stdin.Close()
		_ = childStdout.Close()
		_ = stdout.Close()
		return nil, err
	}
	// The child holds its pipe ends now; the parent's copies of the
	// child's ends must go, or reads never see EOF after the child exits.
	_ = childStdin.Close()
	_ = childStdout.Close()
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
	stdin  *os.File
	stdout *os.File
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
			// The group kill reaches the children the command spawned;
			// killing only the shell would leak them holding the pipes.
			_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
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

func (c *commandConn) LocalAddr() net.Addr                { return commandAddr{c.addr} }
func (c *commandConn) RemoteAddr() net.Addr               { return commandAddr{c.addr} }
func (c *commandConn) SetReadDeadline(t time.Time) error  { return c.stdout.SetReadDeadline(t) }
func (c *commandConn) SetWriteDeadline(t time.Time) error { return c.stdin.SetWriteDeadline(t) }
func (c *commandConn) SetDeadline(t time.Time) error {
	if err := c.stdin.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.stdout.SetReadDeadline(t)
}

type commandAddr struct{ addr string }

func (a commandAddr) Network() string { return "proxycommand" }
func (a commandAddr) String() string  { return a.addr }
