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

	// The runtime no longer knows the container (it was removed; another
	// container took over the session's name): the record alone must not
	// connect. Replace the state with another session's container.
	if err := rewriteState(t, "cidOther sb.session.id=sidOther\n"); err != nil {
		t.Fatal(err)
	}
	err = execCommand(options{}, "default", "", []string{"true"})
	if err == nil || !strings.Contains(err.Error(), `has no container "cid1"`) {
		t.Fatalf("exec with a container the runtime no longer knows: %v; want a refusal", err)
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
