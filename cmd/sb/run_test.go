package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hrntknr/sb/internal/fakeruntime"
	"github.com/hrntknr/sb/internal/session"
	"github.com/spf13/cobra"
)

// setupRunTest installs the fake runtimes, points sb's session directories
// at a per-test runtime dir, and returns the session lifetime file whose
// removal ends a run.
func setupRunTest(t *testing.T) string {
	t.Helper()
	fakeruntime.Install(t, t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	lifetime := filepath.Join(t.TempDir(), "lifetime")
	if err := os.WriteFile(lifetime, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_FAKE_RUN_LIFETIME", lifetime)
	return lifetime
}

// writeConfig writes a v3 config with a docker runtime and returns its path.
func writeRunConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "version: 3\ncontainer:\n  runtime: docker\n  image: ghcr.io/hrntknr/sh:full\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testOptions builds the run options against the test config.
func testOptions(t *testing.T) options {
	t.Helper()
	return options{configPath: writeRunConfig(t), sshListen: ":0", k8sListen: ":0", awsListen: ":0"}
}

// sessionsDir is this test's session directory.
func sessionsDir(t *testing.T) string {
	t.Helper()
	dir, err := session.SessionsDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
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

// waitForSessionRecord polls until the named session's record exists, so a
// test never races the run's startup.
func waitForSessionRecord(t *testing.T, name string) {
	t.Helper()
	dir := sessionsDir(t)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(session.RecordPath(dir, name)); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session %q: record never appeared", name)
}

// runUntilDone runs a session to completion: it starts the run, waits for
// its record, then ends the run (removing the lifetime file) and returns
// its result. It uses the environment setupRunTest left behind.
func runUntilDone(t *testing.T, name string) error {
	t.Helper()
	lifetime := os.Getenv("SB_FAKE_RUN_LIFETIME")
	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		done <- runContainer(cmd, testOptions(t), name, "", false, nil)
	}()
	waitForSessionRecord(t, name)
	if err := os.Remove(lifetime); err != nil {
		t.Fatal(err)
	}
	err := <-done
	if err != nil {
		t.Fatalf("run %q: %v", name, err)
	}
	return nil
}

// TestRunContainerReclaimsOnExit covers the normal exit: once the run ends,
// the session's container is stopped and removed by label, its issue dir
// and record are gone, and no container of the session is left.
func TestRunContainerReclaimsOnExit(t *testing.T) {
	setupRunTest(t)
	if err := runUntilDone(t, "default"); err != nil {
		t.Fatal(err)
	}
	dir := sessionsDir(t)

	// The session's files are gone: the record, the issue dir.
	if _, err := os.Stat(session.RecordPath(dir, "default")); !os.IsNotExist(err) {
		t.Fatalf("record survived the stop: %v", err)
	}
	issues, err := os.ReadDir(filepath.Join(filepath.Dir(dir), "issues"))
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("issue dirs survived the stop: %v", issues)
	}
	// The lock file stays (the name's stable claim); the lock on it is
	// released: a second run may take the name.
	second, err := session.Acquire(dir, "default")
	if err != nil {
		t.Fatalf("lock file still held after the stop: %v", err)
	}
	second.Release()
	// The session's containers are gone: the fake's state has no container
	// carrying the session label (the run registered exactly one).
	if state := stateText(t); strings.Contains(state, "sb.session.id=") {
		t.Fatalf("container survived the stop: %q", state)
	}
}

// TestRunContainerSweepsOrphans covers the orphan recovery at the next
// startup: the orphan's containers are removed by session label, its record
// and issue dir are gone, even though its own sb never ran again.
func TestRunContainerSweepsOrphans(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// An orphan: a record nobody owns, its container alive under the
	// session label, its issue dir still holding credentials.
	orphanIssueDir, err := session.NewIssueDir("sidOrphan")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphanIssueDir, "key"), []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := session.SaveRecord(dir, session.Record{Name: "orphan", ID: "sidOrphan", Runtime: "docker", IssueDir: orphanIssueDir}); err != nil {
		t.Fatal(err)
	}
	addStateLine(t, "cidOrphan sb.session.id=sidOrphan\n")

	// A new run of a different name sweeps it at startup, then ends.
	if err := runUntilDone(t, "fresh"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.RecordPath(dir, "orphan")); !os.IsNotExist(err) {
		t.Fatalf("orphan record survived the sweep: %v", err)
	}
	if state := stateText(t); strings.Contains(state, "cidOrphan") {
		t.Fatalf("orphan container survived the sweep: %q", state)
	}
	if _, err := os.Stat(filepath.Join(orphanIssueDir, "key")); !os.IsNotExist(err) {
		t.Fatalf("orphan issue dir survived the sweep: %v", err)
	}
}

// TestRunContainerRefusesLiveSessionName covers the name collision refusal:
// starting a second run with a live session's name is refused.
func TestRunContainerRefusesLiveSessionName(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// A live session named "default": the owner holds the lock.
	lock, err := session.Acquire(dir, "default")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err = runContainer(cmd, testOptions(t), "default", "", false, nil)
	if err == nil || !strings.Contains(err.Error(), `session "default" is already running`) {
		t.Fatalf("run with a live session's name: %v; want session \"default\" is already running", err)
	}
}

// TestRunContainerKeepsLiveSessions covers the live session protection:
// another session's startup sweep leaves a live session, its containers,
// and its record alone.
func TestRunContainerKeepsLiveSessions(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// A live session named "default": the owner holds the lock, its
	// container runs under the session label.
	lock, err := session.Acquire(dir, "default")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if err := session.SaveRecord(dir, session.Record{Name: "default", ID: "sidLive", Runtime: "docker", IssueDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	addStateLine(t, "cidLive sb.session.id=sidLive\n")

	// A run of another name sweeps at startup: the live session stays.
	if err := runUntilDone(t, "other"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.LoadRecord(dir, "default"); err != nil {
		t.Fatalf("live session's record swept: %v", err)
	}
	if state := stateText(t); !strings.Contains(state, "cidLive sb.session.id=sidLive\n") {
		t.Fatalf("live session's container swept: %q", state)
	}
}

// waitForStateLine polls the fake runtime's state until it holds a line
// carrying text, so a test never races the CLI's registration.
func waitForStateLine(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stateText(t), text) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fake runtime state never held %q: %q", text, stateText(t))
}

// TestRunContainerStopsWhenOnlySbGetsTheSignal covers the blocker: SIGTERM
// to sb's PID only — the child CLI never exits voluntarily (it ignores
// signals), so nothing but the stop flow may end it. The stop flow must
// complete: communication cut, containers reclaimed, child collected,
// the name free again.
func TestRunContainerStopsWhenOnlySbGetsTheSignal(t *testing.T) {
	setupRunTest(t)
	// The run never ends by itself: the CLI ignores TERM and INT and
	// stays alive until its caller kills it.
	t.Setenv("SB_FAKE_RUN_IGNORE_SIGNALS", "ignore")
	os.Unsetenv("SB_FAKE_RUN_LIFETIME")

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		done <- runContainer(cmd, testOptions(t), "default", "", false, nil)
	}()
	// The child registered the session's container: the run is live past
	// its signal handler — only sb's PID receiving the signal ends it.
	waitForStateLine(t, "sb.session.id=")
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run after the signal: %v", err)
		}
	case <-time.After(2 * time.Minute):
		t.Fatal("the stop flow did not complete after the signal")
	}

	dir := sessionsDir(t)
	// The stop flow completed: the session's record and issue dir are
	// gone, its container is removed, and the name is free again.
	if _, err := os.Stat(session.RecordPath(dir, "default")); !os.IsNotExist(err) {
		t.Fatalf("record survived the stop: %v", err)
	}
	if state := stateText(t); strings.Contains(state, "sb.session.id=") {
		t.Fatalf("container survived the stop: %q", state)
	}
	if lock, err := session.Acquire(dir, "default"); err != nil {
		t.Fatalf("lock still held after the stop: %v", err)
	} else {
		lock.Release()
	}
}

// TestRunContainerRefusesUnreclaimedRecord covers the reuse refusal through
// the run flow: a name whose record survived a failed sweep (a runtime the
// sweep cannot even name) is refused — its containers are unreclaimed, and
// the record is what a retry needs. Another name still runs fine.
func TestRunContainerRefusesUnreclaimedRecord(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// An orphan with an unresolvable runtime: the sweep fails before
	// touching its containers and keeps the record.
	if err := session.SaveRecord(dir, session.Record{Name: "orphan", ID: "sidOrphan", Runtime: "banana", IssueDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	addStateLine(t, "cidOrphan sb.session.id=sidOrphan\n")

	// A run of another name sweeps at startup: the sweep fails, the
	// orphan's record stays — and the run proceeds on its own name.
	if err := runUntilDone(t, "fresh"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.LoadRecord(dir, "orphan"); err != nil {
		t.Fatalf("orphan record dropped by the failed sweep: %v", err)
	}

	// The unreclaimed name is refused: its record stays until the
	// containers are gone by hand.
	_, err := session.Acquire(dir, "orphan")
	if err == nil {
		t.Fatal("Acquire() for an unreclaimed name, want a refusal")
	}
	// The refusal carries what a hand-recovery needs: the recovery
	// steps with the session's own label, whatever runtime it names.
	for _, want := range []string{
		"reclaim them by hand",
		"runtime banana",
		"session id sidOrphan",
		"--filter label=sb.session.id=sidOrphan",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal = %q, want it to contain %q", err.Error(), want)
		}
	}
}

// recordNames returns the names the session records in dir carry.
func recordNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var rec session.Record
		if json.Unmarshal(data, &rec) == nil && rec.Name != "" {
			names = append(names, rec.Name)
		}
	}
	return names
}

// TestRunContainerGeneratesNamesWhenOmitted covers the name generation: a
// run without --name gets its own generated name, so a second run the
// same way runs beside the first instead of refusing its name.
func TestRunContainerGeneratesNamesWhenOmitted(t *testing.T) {
	setupRunTest(t)
	lifetime := os.Getenv("SB_FAKE_RUN_LIFETIME")
	dir := sessionsDir(t)

	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			done <- runContainer(cmd, testOptions(t), "", "", false, nil)
		}()
	}

	// Both runs are live at once: two records, two different names.
	deadline := time.Now().Add(10 * time.Second)
	var names []string
	for time.Now().Before(deadline) {
		if names = recordNames(t, dir); len(names) == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(names) != 2 {
		t.Fatalf("two nameless runs: %d records, want 2", len(names))
	}
	if names[0] == names[1] {
		t.Fatalf("two nameless runs share the name %q", names[0])
	}

	// Both runs end when the lifetime file goes.
	if err := os.Remove(lifetime); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	// No name is left claimed and no container is left behind.
	if names = recordNames(t, dir); len(names) != 0 {
		t.Fatalf("records survived the stop: %v", names)
	}
	if state := stateText(t); strings.Contains(state, "sb.session.id=") {
		t.Fatalf("containers survived the stop: %q", state)
	}
}
