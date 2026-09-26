package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestWithoutExitCodeKeepsTheWrappedStory covers the wrapped form: a
// single-part wrapper (fmt.Errorf's %w) around a Join of the exit code
// and what failed around it. The wrapper is not dropped for carrying
// the exit code: what failed around it survives the drop — a wrapper
// dropped because an errors.As found the code inside it would erase
// the cleanup's story with it.
func TestWithoutExitCodeKeepsTheWrappedStory(t *testing.T) {
	wrapped := fmt.Errorf("run: %w", errors.Join(&exitCodeError{code: 42}, fmt.Errorf("cleanup failed")))

	// What failed around the exit code: kept — a wrapper dropped for
	// carrying an exit code would erase the cleanup's story with it.
	rest := withoutExitCode(wrapped)
	if rest == nil {
		t.Fatal("withoutExitCode(wrapped) = nothing; want the cleanup's story")
	}
	if !strings.Contains(rest.Error(), "cleanup failed") {
		t.Fatalf("rest = %q; want the cleanup's story", rest.Error())
	}

	// The exit code alone, wrapped the same way: dropped — nothing
	// failed around it, nothing shows.
	if rest := withoutExitCode(fmt.Errorf("run: %w", &exitCodeError{code: 42})); rest != nil {
		t.Fatalf("withoutExitCode(wrapped exit code alone) = %v; want nothing", rest)
	}
}
