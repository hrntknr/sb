package sshproxy

import (
	"context"
	"net"
	"sync"
)

// Shutdown stops the proxy's downstream connections: new connections are
// rejected, open ones are closed, cancelling their transfers and upstream
// requests, and Shutdown waits for the last connection's cleanup to finish.
// ctx bounds the wait; after its deadline, Shutdown returns.
func (p *Proxy) Shutdown(ctx context.Context) {
	p.conns.closeAll()
	p.conns.wait(ctx)
}

// connSet tracks open downstream connections so they can all be closed at
// once.
type connSet struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	conns  map[net.Conn]struct{}
}

// track registers a downstream connection. It reports false once shutdown
// started: the connection is then closed by its acceptor and nothing may
// join the session anymore.
func (c *connSet) track(conn net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if c.conns == nil {
		c.conns = map[net.Conn]struct{}{}
	}
	c.conns[conn] = struct{}{}
	c.wg.Add(1)
	return true
}

// untrack marks one connection's cleanup done; it has left the set.
func (c *connSet) untrack(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.conns, conn)
	c.wg.Done()
}

// closeAll closes every tracked connection: their transfers and upstream
// requests are cancelled by the cleanup this triggers.
func (c *connSet) closeAll() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	conns := make([]net.Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// wait returns when every tracked connection's cleanup finished or ctx
// ends; the deadline keeps a stuck cleanup from holding the stop flow.
func (c *connSet) wait(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
