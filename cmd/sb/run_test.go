package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
// at per-test dirs (the state dir for the records and locks, the runtime
// dir for the issue dirs), and returns the session lifetime file whose
// removal ends a run.
func setupRunTest(t *testing.T) string {
	t.Helper()
	fakeruntime.Install(t, t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	lifetime := filepath.Join(t.TempDir(), "lifetime")
	if err := os.WriteFile(lifetime, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_FAKE_START_LIFETIME", lifetime)
	return lifetime
}

// writeConfig writes a v3 config with a docker runtime and returns its path.
func writeRunConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "container:\n  runtime: docker\n  image: ghcr.io/hrntknr/sh:full\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testOptions builds the run options against the test config. The run
// flow derives its own listen addresses — none of sb proxy's flag
// defaults flow into it — so the options carry nothing of the proxies.
func testOptions(t *testing.T) options {
	t.Helper()
	return options{configPath: writeRunConfig(t)}
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
	lifetime := os.Getenv("SB_FAKE_START_LIFETIME")
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
	// The issue dir lives under the runtime dir's sb tree (the state
	// dir holds the records and locks).
	issues, err := os.ReadDir(filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "sb", "issues"))
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

// waitForContainerID polls until the named session's record carries the
// container ID: the creation settled — its result fixed — so a test never
// races the run's startup.
func waitForContainerID(t *testing.T, name string) {
	t.Helper()
	dir := sessionsDir(t)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if rec, err := session.LoadRecord(dir, name); err == nil && rec.ContainerID != "" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session %q: container ID never recorded", name)
}

// waitForCreateCall polls until the runtime CLI was called to create the
// container: the creation started, its result not yet settled. That is the
// sync point between the run and what observes it — a stop or a sweep
// that lands here may not settle what the runtime has not committed.
func waitForCreateCall(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(os.Getenv("SB_TEST_CALLS_LOG")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "create ") {
					return
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the create CLI was never called")
}

// runRootCommand runs sb through the real root command: the production
// wiring — flag parsing, the defaults, the run flow — not a test-local
// substitute. What it returns is the run's own result.
func runRootCommand(args ...string) error {
	cmd := newRootCommand()
	cmd.SetArgs(args)
	return cmd.Execute()
}

// primaryIP returns the host's source address for outbound traffic: the
// address a connection from beyond the host's loopback arrives at — the
// same route a bridge container's connection takes to the host. It sends
// no packets (a UDP connect consults the routing table only), and reports
// an error when there is no route to take.
func primaryIP() (string, error) {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	if ip == nil || ip.IsLoopback() {
		return "", fmt.Errorf("the outbound address %v is not beyond loopback", ip)
	}
	return ip.String(), nil
}

// sshConfigTarget parses the generated ssh config: the host the
// credentials point the container at, and the port the proxy listens on.
// Each is the first of its key in the file (the proxy's own block).
func sshConfigTarget(t *testing.T, path string) (host, port string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "HostName":
			host = fields[1]
		case "Port":
			if port == "" {
				port = fields[1]
			}
		}
	}
	if host == "" || port == "" {
		t.Fatalf("generated ssh config: no target under %s", path)
	}
	return host, port
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
	t.Setenv("SB_FAKE_START_IGNORE_SIGNALS", "ignore")
	os.Unsetenv("SB_FAKE_START_LIFETIME")

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		done <- runContainer(cmd, testOptions(t), "default", "", false, nil)
	}()
	// The creation settled: the run is live past its signal handler —
	// only sb's PID receiving the signal ends it.
	waitForContainerID(t, "default")
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

// TestRunContainerKeepsTheRecordWhileTheCreationIsInFlight covers the
// blocker: a stop that lands while the creation is still in flight. What
// the stop's listing answers about the session is not the whole truth —
// the runtime may still commit the creation — so the stop may not settle
// the reclaim on it: the record stays, and whatever the creation commits
// after sb is gone is the next sweep's to reclaim.
func TestRunContainerKeepsTheRecordWhileTheCreationIsInFlight(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// The creation is in flight: the CLI does not answer while this
	// exists.
	slow := filepath.Join(t.TempDir(), "slow")
	if err := os.WriteFile(slow, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_FAKE_CREATE_SLOW", slow)

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		done <- runContainer(cmd, testOptions(t), "default", "", false, nil)
	}()
	waitForSessionRecord(t, "default")
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		// The stop kept the record: nothing of the session is settled on
		// the listing's answer while the creation is in flight.
		if err == nil {
			t.Fatal("run: want the record kept for the next sweep")
		}
	case <-time.After(2 * time.Minute):
		t.Fatal("the stop flow did not complete after the signal")
	}

	// The record stays: nothing of the session is dropped.
	if _, err := os.Stat(session.RecordPath(dir, "default")); os.IsNotExist(err) {
		t.Fatal("record dropped while the creation was in flight")
	}

	// Whatever the creation commits after sb is gone — the runtime
	// completing it — is the next sweep's to reclaim. The creation no
	// longer in flight, the next run's own creation settles normally:
	// model the container existing now, then sweep it away.
	os.Remove(slow)
	t.Setenv("SB_FAKE_CREATE_SLOW", "")
	rec, err := session.LoadRecord(dir, "default")
	if err != nil {
		t.Fatal(err)
	}
	addStateLine(t, "cidLate sb.session.id="+rec.ID+"\n")
	if err := runUntilDone(t, "fresh"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.RecordPath(dir, "default")); !os.IsNotExist(err) {
		t.Fatalf("record survived the sweep: %v", err)
	}
	if state := stateText(t); strings.Contains(state, "cidLate") {
		t.Fatalf("container survived the sweep: %q", state)
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
	// The creation's result is unsettled, so the advice is the
	// unsettle form: the record is what the next sweep retries with,
	// not the by-hand reclaim named outright.
	for _, want := range []string{
		"next sweep retries with this record",
		"creation request has ended",
		"runtime banana",
		"session id sidOrphan",
		"--filter label=sb.session.id=sidOrphan",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal = %q, want it to contain %q", err.Error(), want)
		}
	}
}

// TestRunContainerExitWithFailedRemovalShowsRecovery covers the failed
// run: the container exits 42 and the removal fails. The run's error keeps
// the container's exit code (sb's own) and what failed around it: what
// main prints on stderr — withoutExitCode — carries the recovery steps,
// while the exit code part is kept for sb's exit, not stderr.
func TestRunContainerExitWithFailedRemovalShowsRecovery(t *testing.T) {
	setupRunTest(t)
	// The removal answers without removing: the containers stay behind
	// the call, the reclamation fails.
	linger := filepath.Join(t.TempDir(), "linger")
	if err := os.WriteFile(linger, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_FAKE_RM_LINGER", linger)
	// The container exits 42 once its wait is over.
	t.Setenv("SB_FAKE_START_EXIT_CODE", "42")

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		done <- runContainer(cmd, testOptions(t), "default", "", false, nil)
	}()
	waitForSessionRecord(t, "default")
	if err := os.Remove(os.Getenv("SB_FAKE_START_LIFETIME")); err != nil {
		t.Fatal(err)
	}
	err := <-done
	if err == nil {
		t.Fatal("run: want the joined failure")
	}

	// The container's exit code is sb's.
	var code *exitCodeError
	if !errors.As(err, &code) {
		t.Fatalf("run %v: no exit code kept", err)
	}
	if code.code != 42 {
		t.Fatalf("run %v: exit code %d kept, want 42", err, code.code)
	}

	// What failed around it still shows: the stderr part (without the
	// exit code) carries the recovery steps.
	rest := withoutExitCode(err)
	if rest == nil {
		t.Fatal("withoutExitCode: nothing; want the reclamation failure")
	}
	for _, want := range []string{"reclaim them by hand", "docker ps -aq --filter label=sb.session.id="} {
		if !strings.Contains(rest.Error(), want) {
			t.Fatalf("stderr part = %q, want it to contain %q", rest.Error(), want)
		}
	}
	// The exit code part is not the stderr's: what sb keeps for itself.
	if strings.Contains(rest.Error(), "exit status 42") {
		t.Fatalf("stderr part = %q; want the exit code kept out of it", rest.Error())
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
	lifetime := os.Getenv("SB_FAKE_START_LIFETIME")
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

// TestRunSweepFailureShowsOnStderr covers the orphan reclaim failure's
// report: whatever the log level (the default drops log lines), the
// sweep's failure must be on stderr — the orphans stay for the next
// sweep, and nothing else will say why.
func TestRunSweepFailureShowsOnStderr(t *testing.T) {
	setupRunTest(t)
	// An orphan whose reclaim fails: its runtime does not resolve, so
	// the sweep cannot remove its containers and keeps its record.
	sessions := sessionsDir(t)
	if err := session.SaveRecord(sessions, session.Record{
		Name: "orphan", ID: "sidOrphan", Runtime: "sb-missing", IssueDir: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}

	// stderr carries the sweep's failure whatever the log level: the
	// capture holds it while the run uses it.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = saved })

	// The run proceeds: the orphan's failure is background — the run's
	// own session starts and reclaims cleanly after it.
	if err := runUntilDone(t, "default"); err != nil {
		t.Fatal(err)
	}

	// The sweep's failure is on stderr: what stayed, and why.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "session sweep failed") {
		t.Fatalf("stderr does not carry the sweep's failure: %q", out)
	}
	if !strings.Contains(string(out), "sb-missing") {
		t.Fatalf("stderr does not name what stayed behind: %q", out)
	}
	// The orphan's record stays: the next sweep retries with it.
	if _, err := session.LoadRecord(sessions, "orphan"); err != nil {
		t.Fatalf("orphan's record did not stay: %v", err)
	}
}

// TestSweepKeepsAnUnsettledCreationUntilItsEnd covers the ordering that
// loses containers: a sweep that lands between the creation's start and
// the runtime's commit. The record's persisted state — the creation not
// settled — is what the sweep reads: an empty listing is not the
// creation's end, so the record stays, and the container the runtime
// commits after it is the next sweep's to reclaim.
func TestSweepKeepsAnUnsettledCreationUntilItsEnd(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// The creation is in flight: the CLI does not answer while this
	// exists, and the runtime commits nothing for the session until it.
	slow := filepath.Join(t.TempDir(), "slow")
	if err := os.WriteFile(slow, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_FAKE_CREATE_SLOW", slow)

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		done <- runContainer(cmd, testOptions(t), "default", "", false, nil)
	}()
	// The sync point: the creation started — its result is in flight.
	// The stop that follows lands on a creation the runtime may still
	// commit, so the record stays for the next sweep.
	waitForCreateCall(t)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("run: want the record kept for the next sweep")
	}

	// A sweep before the creation completes: the listing is empty (the
	// runtime has not committed), and the record's own state — not the
	// listing — decides. The record stays, and with it the issue dir:
	// what the creation commits after the sweep is the next sweep's to
	// reclaim, and the issue dir is what a retry needs.
	if err := session.Sweep(dir); err == nil {
		t.Fatal("sweep: want the record kept for the next sweep")
	}
	if _, err := os.Stat(session.RecordPath(dir, "default")); os.IsNotExist(err) {
		t.Fatal("record dropped on an empty listing while the creation was in flight")
	}
	rec, err := session.LoadRecord(dir, "default")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rec.IssueDir); os.IsNotExist(err) {
		t.Fatal("issue dir dropped while the creation was in flight")
	}

	// The creation completes after the sweep: the runtime commits the
	// container. Nothing of sb's is left to settle it — the record is
	// what the next sweep needs.
	addStateLine(t, "cidLate sb.session.id="+rec.ID+"\n")

	// The next sweep reclaims it: the listing finds the container, the
	// removal confirms the creation's end, and the record goes.
	if err := session.Sweep(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.RecordPath(dir, "default")); !os.IsNotExist(err) {
		t.Fatal("record survived the sweep")
	}
	if state := stateText(t); strings.Contains(state, "cidLate") {
		t.Fatalf("container survived the sweep: %q", state)
	}
}

// TestRunProxyStartFailureDropsTheSession covers the start failure before
// the creation: a proxy component that cannot start returns before the
// create CLI is ever asked of the runtime. Nothing was asked of the
// runtime, nothing will be created — the stop flow may drop the session's
// record and issue dir on the empty listing, and the run's error carries
// only what failed: no unstarted creation's recovery advice.
func TestRunProxyStartFailureDropsTheSession(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// The run's config: a k8s rule (a proxy is started for it) whose
	// upstream source is corrupt — the issuance fails at startup.
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := "k8s:\n  - context: dev\n    resources:\n      - group: \"\"\n        resource: pods\n        namespace: default\n        verbs: [get, list]\ncontainer:\n  runtime: docker\n  image: ghcr.io/hrntknr/sh:full\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("not: a: kubeconfig"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		done <- runContainer(cmd, options{configPath: cfgPath}, "default", "", false, nil)
	}()
	err := <-done
	if err == nil {
		t.Fatal("run: want the proxy start failure")
	}
	// The run's error carries what failed — only that: no creation was
	// started, so no creation's recovery advice may be in it.
	if strings.Contains(err.Error(), "reclaim them by hand") {
		t.Fatalf("run %v: the container was never asked of the runtime; want no recovery advice", err)
	}
	// The session's record and issue dir are gone: nothing was asked
	// of the runtime, nothing will be created for the session.
	if _, err := os.Stat(session.RecordPath(dir, "default")); !os.IsNotExist(err) {
		t.Fatal("record survived a start failure before the creation")
	}
	// The issue dir lives under the runtime dir's sb tree (the state
	// dir holds the records and locks); its base is what the run
	// created there.
	issues := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "sb", "issues")
	entries, err := os.ReadDir(issues)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("issue dirs survived a start failure: %v", entries)
	}
}

// TestRunProxiesReachBeyondLoopbackThroughTheRootCommand covers the run's
// own wiring, through the root command: the run's defaults — not sb
// proxy's — select the listen addresses, and the generated credentials
// point the container at what reaches them. The listener binds every
// interface, and the connection from beyond the host's loopback — the
// same route a bridge container's connection takes onto the host —
// reaches the proxy. A loopback-only listener (sb proxy's safe default
// flowing into the run) would not: the connection would be refused.
func TestRunProxiesReachBeyondLoopbackThroughTheRootCommand(t *testing.T) {
	setupRunTest(t)
	dir := sessionsDir(t)

	// The run's config: an ssh rule (the ssh proxy is started, the
	// generated ssh config points the container at it) and the container
	// section the run needs.
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := "ssh:\n  - host: github.com\n    access: full\ncontainer:\n  runtime: docker\n  image: ghcr.io/hrntknr/sh:full\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// The run through the root command: the real wiring — flag parsing,
	// the run's own defaults — not a test-local substitute.
	lifetime := os.Getenv("SB_FAKE_START_LIFETIME")
	done := make(chan error, 1)
	go func() {
		done <- runRootCommand("run", "--config", cfgPath, "--name", "default", "--", "zsh", "-l")
	}()
	// The creation started: the proxies are up, the credentials issued.
	waitForCreateCall(t)

	rec, err := session.LoadRecord(dir, "default")
	if err != nil {
		t.Fatal(err)
	}
	host, port := sshConfigTarget(t, filepath.Join(rec.IssueDir, ".ssh", "config"))

	// The generated ssh config points the container at the host the
	// runtime's network mode reaches: the fake docker on a bridge —
	// rootful, as the fake's info answers — advertises host.docker.internal.
	if host != "host.docker.internal" {
		t.Fatalf("generated ssh config: HostName %q, want host.docker.internal", host)
	}

	// The listener binds every interface: the connection from beyond the
	// host's loopback — the host's own outbound address, the same route
	// a bridge container's connection takes onto the host — reaches the
	// proxy. A loopback-only listener would refuse it.
	ip, err := primaryIP()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(ip, port), time.Second)
		if dialErr == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s:%s via %q: %v (a loopback-only listener refuses it)", ip, port, ip, dialErr)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// End the run: the container's start ends, and the run's own stop
	// flow reclaims its session.
	if err := os.Remove(lifetime); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.RecordPath(dir, "default")); !os.IsNotExist(err) {
		t.Fatalf("record survived the stop: %v", err)
	}
}
