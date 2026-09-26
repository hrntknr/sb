package util

import (
	"context"
	"time"
)

// StoppedContext returns a context that is done when stop is done (the
// stop began) or when base is, whichever comes first. A context issued
// after the stop began is cancelled from its first use.
func StoppedContext(stop, base context.Context) context.Context {
	if stop == nil {
		return base
	}
	if base == nil {
		return stop
	}
	ctx := &stoppedContext{stop: stop, base: base, done: make(chan struct{})}
	go func() {
		select {
		case <-stop.Done():
		case <-base.Done():
		}
		close(ctx.done)
	}()
	return ctx
}

type stoppedContext struct {
	stop, base context.Context
	done       chan struct{}
}

func (c *stoppedContext) Deadline() (time.Time, bool) { return c.base.Deadline() }
func (c *stoppedContext) Done() <-chan struct{}       { return c.done }
func (c *stoppedContext) Err() error {
	if err := c.stop.Err(); err != nil {
		return err
	}
	return c.base.Err()
}
func (c *stoppedContext) Value(key any) any { return c.base.Value(key) }
