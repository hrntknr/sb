package sshproxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
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
