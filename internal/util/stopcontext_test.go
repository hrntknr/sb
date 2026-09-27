package util

import (
	"context"
	"testing"
	"time"
)

// TestStoppedContextIsCancelledBeforeReturn covers a context issued after
// the stop began: its cancellation must be visible without waiting — a
// Done() that only a goroutine running later closes leaves requests
// waiting for it, whatever Err() already says.
func TestStoppedContextIsCancelledBeforeReturn(t *testing.T) {
	stop, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancel()
	base, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()

	ctx := StoppedContext(stop, base)
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Done() is not receivable right after the return; the stop already began")
	}
	if err := ctx.Err(); err != context.Canceled {
		t.Fatalf("Err() = %v; want context.Canceled", err)
	}
}

// TestStoppedContextEndsItsWatchWithTheBase covers the registration's
// end: the watch on the stop ends when the request it bounds is over,
// so connections that come and go do not leave one watch per request.
func TestStoppedContextEndsItsWatchWithTheBase(t *testing.T) {
	stop, stopCancel := context.WithCancel(context.Background())
	defer stopCancel()
	base, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()

	ctx := StoppedContext(stop, base)
	baseCancel() // the request it bounds is over; nothing watches anymore
	stopCancel() // the stop begins: nothing to cancel for the request
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the context was not done")
	}
}

// TestStoppedContextReleaseEndsTheWatch covers the release's end: the
// watch on the stop ends when the call it carried is over — the
// context it returned is done being used, its Done does not fire
// after that, whatever the stop does.
func TestStoppedContextReleaseEndsTheWatch(t *testing.T) {
	stop, stopCancel := context.WithCancel(context.Background())
	defer stopCancel()
	base, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()

	ctx, release := StoppedContextRelease(stop, base)
	release()    // the call it carried is over: the watch ends with it
	stopCancel() // the stop begins: nothing fires for the context
	select {
	case <-ctx.Done():
		t.Fatal("Done fired after the release; the watch ended with it")
	default:
	}
}
