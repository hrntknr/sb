package sshproxy

import (
	"context"
	"net"
	"sync"
)

// Shutdown waits for the open connections' cleanups: the connections
// themselves are closed by BeginStop — each one's transfers and upstream
// requests cancelled by the cleanup it triggers. ctx bounds the wait;
// after its deadline, Shutdown returns.
func (p *Proxy) Shutdown(ctx context.Context) {
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

// closeAll closes the set itself and every tracked connection: nothing
// may join it anymore, and no connection open at the stop keeps operating
// — its new channels, requests, and data are cut with it. The cleanup
// this triggers cancels its transfers and upstream requests.
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
