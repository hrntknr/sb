package sshproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// TestShutdownCutsStuckCleanupAtDeadline covers the deadline of the stop
// flow: a connection whose cleanup never finishes — a transfer that never
// goes idle — is closed, and Shutdown does not wait for its cleanup past
// the deadline.
func TestShutdownCutsStuckCleanupAtDeadline(t *testing.T) {
	proxy := New(nil, nil)
	server, client := net.Pipe()
	if !proxy.track(server) {
		t.Fatal("track rejected the connection")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	proxy.Shutdown(ctx)
	waited := time.Since(start)
	if waited < 150*time.Millisecond {
		t.Fatalf("Shutdown returned after %v; want it to wait out the deadline", waited)
	}
	if waited > 2*time.Second {
		t.Fatalf("Shutdown waited %v; want it cut at the deadline", waited)
	}

	// The connection was closed: the transfer on it is cancelled.
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the connection was not closed by Shutdown: %v", err)
	}
}

// TestShutdownCutsStuckUpstreamHandshake covers the upstream that never
// completes its handshake: the stop start (the stop context cancelled) cuts
// the dial and handshake at the deadline, closing the connection. Without
// it, a server that accepts but never sends its banner would hold the
// stop flow forever.
func TestShutdownCutsStuckUpstreamHandshake(t *testing.T) {
	// A server that accepts but never sends its SSH banner: the client's
	// handshake waits for it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn // held open, never writing
	}()
	addr := ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = dialUpstreamTCP(ctx, addr, &cryptossh.ClientConfig{})
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("dial waited %v; want it cut at the deadline", waited)
	}
	if err == nil {
		t.Fatal("the handshake completed; want it cut")
	}
	if conn := <-accepted; conn != nil {
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestStoppedProxyCommandCutsTheChild covers a ProxyCommand child that does
// not stop: the stop start (the stop context cancelled) kills it — the child
// is gone within the stop deadline, not waited for. The child publishes the
// shell's pid and its own (a `sleep` it started and waits for): both must
// die — the stop kills the whole process group, not just the shell that
// started it, or the shell's children outlive it holding the pipes.
func TestStoppedProxyCommandCutsTheChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := startProxyCommand(ctx, "echo $$; sleep 3600 & echo $!; wait", "target.example:22")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Both pids on the wire: the shell's, then the child it waits for.
	lines := bufio.NewReader(conn)
	shellPid, childPid := 0, 0
	for i := 0; i < 2; i++ {
		line, err := lines.ReadString('\n')
		if err != nil {
			t.Fatalf("the child did not publish its pid: %v", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			t.Fatalf("the published pid %q is not a pid: %v", line, err)
		}
		if i == 0 {
			shellPid = pid
		} else {
			childPid = pid
		}
	}
	if shellPid == 0 || childPid == 0 || shellPid == childPid {
		t.Fatalf("pids: shell=%d child=%d; want two distinct", shellPid, childPid)
	}
	for _, pid := range []int{shellPid, childPid} {
		if proc, err := os.FindProcess(pid); err != nil || proc == nil {
			t.Skip("process lookup not available")
		} else if err := proc.Signal(syscall.Signal(0)); err != nil {
			t.Skip("the process already exited")
		}
	}
	// A failing test would leak the group; kill both best-effort at the
	// end so no orphan outlives the test either way.
	t.Cleanup(func() {
		_ = syscall.Kill(shellPid, syscall.SIGKILL)
		_ = syscall.Kill(childPid, syscall.SIGKILL)
	})

	// The stop start: the child's process group is killed by the
	// connection's owner.
	cancel()
	pidsGone := func() bool {
		for _, pid := range []int{shellPid, childPid} {
			if err := syscall.Kill(pid, syscall.Signal(0)); err == nil {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(2 * time.Second)
	for !pidsGone() {
		if time.Now().After(deadline) {
			t.Fatalf("the ProxyCommand child survived the stop: shell=%d child=%d", shellPid, childPid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestProxyCommandWatchEndsWithEachConnection covers the watch lifecycle
// over iterated connections: the proxy is not stopped while the
// connections iterate — each connection's watch ends with the
// connection itself, so iterating does not accumulate one watch per
// connection. Without the end, a long-running proxy accumulates a watch
// per connection it ever served.
func TestProxyCommandWatchEndsWithEachConnection(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		conn, err := startProxyCommand(context.Background(), "exit 0", "target.example:22")
		if err != nil {
			t.Fatal(err)
		}
		// The connection ends: Close reaps the child, done closes,
		// the watch ends with it.
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Every watch ended with its connection: none is left waiting
	// for the proxy's stop that never comes.
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("the watches accumulated: %d goroutines before the iteration, %d after", before, runtime.NumGoroutine())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestAgentWatchEndsWithEachAuth covers the agent watch over iterated
// auths: the proxy is not stopped while the auths iterate — each auth's
// watch ends with the auth's own call, so iterating does not accumulate
// one watch per auth.
func TestAgentWatchEndsWithEachAuth(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				// The key list request: read the frame, answer with
				// an empty identities list.
				var length [4]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				request := make([]byte, binary.BigEndian.Uint32(length[:]))
				if _, err := io.ReadFull(conn, request); err != nil {
					return
				}
				answer := []byte{12, 0, 0, 0, 0} // identities answer, count 0
				var answerLength [4]byte
				binary.BigEndian.PutUint32(answerLength[:], uint32(len(answer)))
				if _, err := conn.Write(append(answerLength[:], answer...)); err != nil {
					return
				}
			}(conn)
		}
	}()

	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		signers, conn := sshAgentSigners(context.Background(), listener.Addr().String())
		if len(signers) != 0 {
			t.Fatalf("signers = %v; want none", signers)
		}
		if conn == nil {
			t.Fatal("no connection returned for the auth")
		}
		conn.Close()
	}
	// Every watch ended with its auth: none is left waiting for the
	// proxy's stop that never comes.
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("the watches accumulated: %d goroutines before the iteration, %d after", before, runtime.NumGoroutine())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
