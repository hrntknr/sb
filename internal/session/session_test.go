package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrntknr/sb/internal/fakeruntime"
)

func testSessionsDir(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir, err := SessionsDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustAcquire(t *testing.T, dir, name string) *Lock {
	t.Helper()
	lock, err := Acquire(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	return lock
}

func mustSaveRecord(t *testing.T, dir string, rec Record) {
	t.Helper()
	if err := SaveRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
}

// addStateLine registers a container in the fake runtime's state.
func addStateLine(t *testing.T, line string) {
	t.Helper()
	f, err := os.OpenFile(os.Getenv("SB_FAKE_STATE"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func stateText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("SB_FAKE_STATE"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestAcquireRejectsASecondOwner covers the name collision refusal: while a
// session owns the name, a second owner is refused.
func TestAcquireRejectsASecondOwner(t *testing.T) {
	fakeruntime.Install(t, t.TempDir())
	dir := testSessionsDir(t)

	lock := mustAcquire(t, dir, "default")
	defer lock.Release()

	if _, err := Acquire(dir, "default"); err == nil || !strings.Contains(err.Error(), `session "default" is already running`) {
		t.Fatalf("Acquire() while held: %v; want session \"default\" is already running", err)
	}
	// The name is free again once the owner releases it.
	lock.Release()
	if _, err := Acquire(dir, "default"); err != nil {
		t.Fatalf("Acquire() after release: %v", err)
	}
}

// TestSweepReclaimsOrphans covers the orphan recovery: a session whose lock
// could be taken has no owner, so the sweep stops and removes its
// containers by session label and drops its files.
func TestSweepReclaimsOrphans(t *testing.T) {
	fakeruntime.Install(t, t.TempDir())
	dir := testSessionsDir(t)

	// An orphan: a record naming a runtime and a session id, a lock nobody
	// holds, a container carrying the session label, and an issue dir.
	issueDir, err := NewIssueDir("sidOrphan")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(issueDir, "key"), []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSaveRecord(t, dir, Record{Name: "orphan", ID: "sidOrphan", Runtime: "docker", IssueDir: issueDir})
	addStateLine(t, "cidOrphan sb.session.id=sidOrphan\n")

	if err := Sweep(dir); err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	if _, err := LoadRecord(dir, "orphan"); err == nil {
		t.Fatal("record survived the sweep")
	}
	if _, err := os.Stat(LockPath(dir, "orphan")); !os.IsNotExist(err) {
		t.Fatalf("lock file survived the sweep: %v", err)
	}
	if _, err := os.Stat(filepath.Join(issueDir, "key")); !os.IsNotExist(err) {
		t.Fatalf("issue dir survived the sweep: %v", err)
	}
	for _, line := range strings.Split(stateText(t), "\n") {
		if strings.Contains(line, "sidOrphan") {
			t.Fatalf("container survived the sweep: %q", line)
		}
	}
}

// TestSweepKeepsLiveSessions covers the live session protection: a session
// whose lock is held is alive, so the sweep leaves it — and its containers —
// alone.
func TestSweepKeepsLiveSessions(t *testing.T) {
	fakeruntime.Install(t, t.TempDir())
	dir := testSessionsDir(t)

	// A live session: the owner holds the lock, its container runs.
	lock := mustAcquire(t, dir, "live")
	defer lock.Release()
	mustSaveRecord(t, dir, Record{Name: "live", ID: "sidLive", Runtime: "docker", IssueDir: t.TempDir()})
	addStateLine(t, "cidLive sb.session.id=sidLive\n")

	if err := Sweep(dir); err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	if _, err := LoadRecord(dir, "live"); err != nil {
		t.Fatalf("live session's record swept: %v", err)
	}
	if !strings.Contains(stateText(t), "cidLive sb.session.id=sidLive\n") {
		t.Fatalf("live session's container swept: %q", stateText(t))
	}
}

// TestSweepRetriesWhenRemovalFails covers the kept record: a session whose
// containers could not be removed keeps its record, so the next sweep
// retries.
func TestSweepRetriesWhenRemovalFails(t *testing.T) {
	fakeruntime.Install(t, t.TempDir())
	dir := testSessionsDir(t)

	// The orphan's runtime is not on PATH: the sweep cannot remove its
	// containers and keeps the record for the next sweep.
	mustSaveRecord(t, dir, Record{Name: "orphan", ID: "sidOrphan", Runtime: "docker", IssueDir: t.TempDir()})
	addStateLine(t, "cidOrphan sb.session.id=sidOrphan\n")
	t.Setenv("PATH", "/nonexistent") // no runtime at all

	if err := Sweep(dir); err == nil {
		t.Fatal("Sweep() succeeded without a runtime, want error")
	}
	if _, err := LoadRecord(dir, "orphan"); err != nil {
		t.Fatalf("record dropped when removal failed: %v", err)
	}
}
