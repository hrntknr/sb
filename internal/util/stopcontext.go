package util

import (
	"context"
	"time"
)

// StoppedContext returns a context that is done when stop is done (the
// stop began) or when base is, whichever comes first. A context issued
// after the stop began is cancelled before it is returned: its Done is
// receivable from the first use, like a standard cancelled context's.
func StoppedContext(stop, base context.Context) context.Context {
	if stop == nil {
		return base
	}
	if base == nil {
		return stop
	}
	ctx := &stoppedContext{stop: stop, base: base, done: make(chan struct{})}
	if stop.Err() != nil {
		// The stop already began: the context is cancelled here, not
		// by a goroutine that runs later.
		close(ctx.done)
		return ctx
	}
	// The rest is done when the stop begins or the base ends, whichever
	// comes first. The close is unconditional: a reader waiting on Done
	// is unblocked when the base ends too, not only when the stop began.
	// The watch ends when either did: nothing tracks the stop anymore.
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
