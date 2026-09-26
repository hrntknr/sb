package main

import (
	"os"
	"strings"
	"testing"

	"github.com/hrntknr/sb/internal/session"
)

// TestExecCommandCrossChecksTheRuntime covers the cross-check that protects
// exec: the session record alone connects to nothing — the runtime's own
// records must still know the container and the session label.
func TestExecCommandCrossChecksTheRuntime(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// A live session: the owner holds the lock, the runtime has its
	// container under the session label.
	lock, err := session.Acquire(dir, "default")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	issueDir := t.TempDir()
	if err := session.SaveRecord(dir, session.Record{Name: "default", ID: "sid1", Runtime: "docker", IssueDir: issueDir, ContainerID: "cid1"}); err != nil {
		t.Fatal(err)
	}
	addStateLine(t, "cid1 sb.session.id=sid1\n")

	// The container is known and carries the label: exec connects to it.
	if err := execCommand(options{}, "default", "", []string{"true"}); err != nil {
		t.Fatalf("exec into the live session: %v", err)
	}

	// Each half of the cross-check fails on its own: the container known
	// but carrying another session's label, the session's label on
	// another container — and neither matching at all.
	for _, state := range []string{
		"cid1 sb.session.id=sidX\n",         // the container's, not the session's
		"cidOther sb.session.id=sid1\n",     // the session's, on another container
		"cidOther sb.session.id=sidOther\n", // neither matches the record
	} {
		if err := rewriteState(t, state); err != nil {
			t.Fatal(err)
		}
		err := execCommand(options{}, "default", "", []string{"true"})
		if err == nil || !strings.Contains(err.Error(), `has no container "cid1"`) {
			t.Fatalf("exec with %q: %v; want a refusal", state, err)
		}
	}

	// The session's lock is gone (its owner exited): exec must refuse.
	lock.Release()
	err = execCommand(options{}, "default", "", []string{"true"})
	if err == nil || !strings.Contains(err.Error(), `session "default" is not running`) {
		t.Fatalf("exec into a dead session: %v; want a refusal", err)
	}
}

// TestExecCommandRefusesMissingSession covers the no-record path: a name
// nothing owns connects to nothing.
func TestExecCommandRefusesMissingSession(t *testing.T) {
	setupRunTest(t)

	err := execCommand(options{}, "missing", "", []string{"true"})
	if err == nil || !strings.Contains(err.Error(), `exec: no session "missing"`) {
		t.Fatalf("exec with no session: %v; want a refusal", err)
	}
}

// rewriteState replaces the fake runtime's state wholesale.
func rewriteState(t *testing.T, content string) error {
	t.Helper()
	return os.WriteFile(os.Getenv("SB_FAKE_STATE"), []byte(content), 0o600)
}
