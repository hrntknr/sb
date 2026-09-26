package session

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hrntknr/sb/internal/fakeruntime"
	"golang.org/x/sys/unix"
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
	// The lock file stays (the name's stable claim); the lock on it is
	// released: another owner may take the name.
	if lock, err := Acquire(dir, "orphan"); err != nil {
		t.Fatalf("lock file still held after the sweep: %v", err)
	} else {
		lock.Release()
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

// TestAcquireRefusesUnreclaimedRecord covers the reuse refusal: a name
// whose record survived a failed removal is not free — its containers are
// unreclaimed, and the record is what a retry needs. Nothing may overwrite
// it until they are gone by hand.
func TestAcquireRefusesUnreclaimedRecord(t *testing.T) {
	fakeruntime.Install(t, t.TempDir())
	dir := testSessionsDir(t)

	// The record a failed removal left: containers under the session
	// label, an issue dir, a runtime.
	mustSaveRecord(t, dir, Record{Name: "orphan", ID: "sidOrphan", Runtime: "docker", IssueDir: t.TempDir(), ContainerID: "cidOrphan"})
	addStateLine(t, "cidOrphan sb.session.id=sidOrphan\n")

	_, err := Acquire(dir, "orphan")
	if err == nil {
		t.Fatal("Acquire() with an unreclaimed record, want a refusal")
	}
	for _, want := range []string{
		"reclaim them by hand",
		"runtime docker",
		"session id sidOrphan",
		"container id \"cidOrphan\"",
		"docker ps -aq --filter label=sb.session.id=sidOrphan",
		"rm -rf ",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Acquire() refusal = %q, want it to contain %q", err.Error(), want)
		}
	}
	// The lock itself is free (nobody holds it) — only the record blocks
	// the reuse, and it stays until the containers are gone by hand.
	if lock, err := Acquire(dir, "other"); err != nil {
		t.Fatalf("Acquire() for another name: %v", err)
	} else {
		lock.Release()
	}
}

// TestStopSessionKeepsTheRecordOnFailedRemoval covers what the stop flow
// keeps: a removal that could not finish leaves the record and the issue
// dir for the next sweep, and releases the lock either way.
func TestStopSessionKeepsTheRecordOnFailedRemoval(t *testing.T) {
	fakeruntime.Install(t, t.TempDir())
	dir := testSessionsDir(t)

	// A running session's record: the removal fails (no runtime at all).
	// The lock first (as the owner would take it), then the record.
	lock := mustAcquire(t, dir, "orphan")
	mustSaveRecord(t, dir, Record{Name: "orphan", ID: "sidOrphan", Runtime: "docker", IssueDir: t.TempDir()})
	addStateLine(t, "cidOrphan sb.session.id=sidOrphan\n")
	t.Setenv("PATH", "/nonexistent")

	err := StopSession(dir, "orphan", lock, true)
	if err == nil {
		t.Fatal("StopSession() succeeded without a runtime, want error")
	}
	if !strings.Contains(err.Error(), "reclaim them by hand") {
		t.Fatalf("StopSession() error = %q, want the hand-reclaim steps", err.Error())
	}
	// The record stays: the next sweep retries with it.
	if _, err := LoadRecord(dir, "orphan"); err != nil {
		t.Fatalf("record dropped on a failed removal: %v", err)
	}
	// The lock is released (nobody holds it): only the record blocks the
	// name, and it stays until the containers are gone by hand.
	if LockHeld(dir, "orphan") {
		t.Fatal("lock still held after the stop")
	}
}

// TestHelperLockHolder is not a test; the session tests run it as a
// subprocess to hold a session lock from another process. It acquires
// the named session's lock, touches the ready file, holds the lock until
// the parent's done file appears, then releases it and exits.
func TestHelperLockHolder(t *testing.T) {
	dir := os.Getenv("SB_TEST_HELPER_DIR")
	name := os.Getenv("SB_TEST_HELPER_NAME")
	ready := os.Getenv("SB_TEST_HELPER_READY")
	done := os.Getenv("SB_TEST_HELPER_DONE")
	if dir == "" || name == "" || ready == "" || done == "" {
		return // not running as a helper
	}
	lock, err := Acquire(dir, name)
	if err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(ready, []byte("held"), 0o600); err != nil {
		os.Exit(3)
	}
	// Hold the lock (the same inode the parent's stop left behind) until
	// the parent is done checking.
	for {
		if _, err := os.Stat(done); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	lock.Release()
}

// TestLockFileIsTheNamesStableClaim covers what the stop leaves behind:
// the lock file stays (another process locking the same inode keeps a
// third one out; a fresh file over a deleted one would not), and the
// lock on it does not — after the stop, the name may be taken again.
func TestLockFileIsTheNamesStableClaim(t *testing.T) {
	dir := testSessionsDir(t)
	fakeruntime.Install(t, t.TempDir())
	signals := t.TempDir()
	ready, done := filepath.Join(signals, "ready"), filepath.Join(signals, "done")

	// Hold the name from a second process: it takes the same lock file's
	// inode (the one the stop will leave behind), touches ready, and
	// waits for done.
	holder := startLockHolder(t, dir, "default", ready, done)
	waitForFile(t, ready)
	// While the holder has the lock (this process's stop flow would
	// leave the file behind and free the lock), nothing may take the
	// name: the same inode is not free, whatever would run next.
	if _, err := Acquire(dir, "default"); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("Acquire() while another process holds the lock: %v; want a refusal", err)
	}

	// Let the holder go: the lock file stays, the lock does not — the
	// name may be taken again, through the same file.
	writeFile(t, done)
	waitForExit(t, holder)

	lock, err := Acquire(dir, "default")
	if err != nil {
		t.Fatalf("Acquire() after the holder released: %v", err)
	}
	lock.Release()
}

// startLockHolder runs the lock holder helper: it acquires the named
// session's lock, touches ready, holds the lock until done appears, then
// releases it and exits.
func startLockHolder(t *testing.T, dir, name, ready, done string) *exec.Cmd {
	t.Helper()
	testExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(testExe, "-test.run=^TestHelperLockHolder$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"SB_TEST_HELPER_DIR="+dir,
		"SB_TEST_HELPER_NAME="+name,
		"SB_TEST_HELPER_READY="+ready,
		"SB_TEST_HELPER_DONE="+done,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// TestDeleteRecordKeepsTheNamesClaim covers the record deletion through
// the lock it runs on: with the lock file unlinked here, another process
// holding the old inode's lock would not keep a later acquirer out — the
// name could be taken twice. The claim (the lock file) must survive the
// deletion.
func TestDeleteRecordKeepsTheNamesClaim(t *testing.T) {
	dir := testSessionsDir(t)
	signals := t.TempDir()
	ready := filepath.Join(signals, "ready")
	lockSignal := filepath.Join(signals, "lock")
	held := filepath.Join(signals, "held")
	done := filepath.Join(signals, "done")

	// sb holds the name; the lock file is the claim on it.
	lock, err := Acquire(dir, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Another process opens the same lock file's inode — what a second sb
	// (or a restarted runtime) would have while the file exists — and
	// waits.
	opener := startLockOpener(t, dir, "default", ready, lockSignal, held, done)
	waitForFile(t, ready)

	// The stop flow's record deletion: it runs with the old inode open.
	if err := lock.DeleteRecord(dir, "default"); err != nil {
		t.Fatal(err)
	}

	// The opener takes the lock on the same inode: the claim must still
	// hold the name — the deletion must not have unlinked it.
	writeFile(t, lockSignal)
	waitForFile(t, held)
	if _, err := Acquire(dir, "default"); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("Acquire() while another process holds the deleted record's lock file: %v; want a refusal", err)
	}

	// Released: the name may be taken again, through the same file.
	writeFile(t, done)
	waitForExit(t, opener)
	after, err := Acquire(dir, "default")
	if err != nil {
		t.Fatalf("Acquire() after the opener released: %v", err)
	}
	after.Release()
}

// TestHelperLockOpener is not a test; the session tests run it as a
// subprocess to keep a session lock file open from another process. It
// opens the named session's lock file (the same inode), touches ready,
// waits for the lock signal, then takes the lock, touches held, waits for
// the done signal, and closes without deleting anything.
func TestHelperLockOpener(t *testing.T) {
	dir := os.Getenv("SB_TEST_HELPER_DIR")
	name := os.Getenv("SB_TEST_HELPER_NAME")
	ready := os.Getenv("SB_TEST_HELPER_READY")
	lockSignal := os.Getenv("SB_TEST_HELPER_LOCK")
	held := os.Getenv("SB_TEST_HELPER_HELD")
	done := os.Getenv("SB_TEST_HELPER_DONE")
	if dir == "" || name == "" || ready == "" || lockSignal == "" || held == "" || done == "" {
		return // not running as a helper
	}
	f, err := os.OpenFile(LockPath(dir, name), unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(ready, []byte("open"), 0o600); err != nil {
		os.Exit(3)
	}
	helperWaitFor(lockSignal)
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		os.Exit(4)
	}
	if err := os.WriteFile(held, []byte("held"), 0o600); err != nil {
		os.Exit(5)
	}
	helperWaitFor(done)
	f.Close()
}

// helperWaitFor waits for a signal file to appear, polling the way the
// lock helpers do.
func helperWaitFor(path string) {
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// startLockOpener runs the lock opener helper: it opens the named session's
// lock file (the same inode), takes the lock at the lock signal, holds it
// until the done signal, then closes without deleting anything.
func startLockOpener(t *testing.T, dir, name, ready, lockSignal, held, done string) *exec.Cmd {
	t.Helper()
	testExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(testExe, "-test.run=^TestHelperLockOpener$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"SB_TEST_HELPER_DIR="+dir,
		"SB_TEST_HELPER_NAME="+name,
		"SB_TEST_HELPER_READY="+ready,
		"SB_TEST_HELPER_LOCK="+lockSignal,
		"SB_TEST_HELPER_HELD="+held,
		"SB_TEST_HELPER_DONE="+done,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
}

func waitForExit(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("helper did not exit")
	}
}

// TestSessionsDirFallsBackPerUser covers the fallback: without a usable
// XDG_RUNTIME_DIR, the sessions live under this user's own subtree of the
// temp dir — never a shared path another user could write into. The test
// runs in its own temp root: the real <tmp>/sb-<uid> (a running sb's
// records, issuances, and lock paths) is outside it and survives the run
// untouched.
func TestSessionsDirFallsBackPerUser(t *testing.T) {
	// The real temp dir is where a running sb's fallback lives; the test
	// falls back inside its own root instead.
	realTemp := os.TempDir()
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	t.Setenv("XDG_RUNTIME_DIR", "") // set but empty: not a usable runtime dir
	real := filepath.Join(realTemp, fmt.Sprintf("sb-%d", os.Getuid()))
	before := dirSnapshot(real)
	t.Cleanup(func() {
		if after := dirSnapshot(real); !slices.Equal(after, before) {
			t.Errorf("the real %s changed: %v -> %v", real, before, after)
		}
	})

	dir, err := SessionsDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, fmt.Sprintf("sb-%d", os.Getuid()), "sb", "sessions"); dir != want {
		t.Fatalf("SessionsDir() = %q, want %q", dir, want)
	}
	// What the run created is this user's and 0700.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("sessions dir mode is %o, want 0700", info.Mode().Perm())
	}
	if owner, ok := ownerOf(info); !ok || owner != uid() {
		t.Fatalf("sessions dir owner is %d (ok=%v), want uid %d", owner, ok, uid())
	}
}

// dirSnapshot lists a directory's entry names, sorted; a nil result is a
// directory that does not exist.
func dirSnapshot(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		// Unreadable for another reason: report nothing — the caller's
		// comparison flags the change.
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

// TestSessionsDirRefusesAWiderDir covers the existing-dir condition: a
// directory left too open (0755 — say another session umask'ed it) is
// refused; sb does not write session records into it.
func TestSessionsDirRefusesAWiderDir(t *testing.T) {
	runtime := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	sb := filepath.Join(runtime, "sb")
	if err := os.MkdirAll(sb, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sb, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := SessionsDir(); err == nil || !strings.Contains(err.Error(), "mode is 755, want 0700") {
		t.Fatalf("SessionsDir() with a 0755 dir: %v; want a refusal", err)
	}
}

// TestSessionsDirRefusesAWrongParentMode covers the fallback's parent: a
// <tmp>/sb-<uid> left too open (0755 — say another user umask'ed it) is
// refused — what sb writes under it would sit in a too-open tree.
func TestSessionsDirRefusesAWrongParentMode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	t.Setenv("XDG_RUNTIME_DIR", "")
	parent := filepath.Join(os.TempDir(), fmt.Sprintf("sb-%d", os.Getuid()))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := SessionsDir(); err == nil || !strings.Contains(err.Error(), "mode is 755, want 0700") {
		t.Fatalf("SessionsDir() with a 0755 parent: %v; want a refusal", err)
	}
}

// TestSessionsDirRefusesAWrongParentOwner covers the fallback's parent: a
// <tmp>/sb-<uid> that exists as another user's (uid 1 here) is refused —
// what sb writes under it would sit in another user's tree, where a rename
// could swap sb's own subtree under it.
func TestSessionsDirRefusesAWrongParentOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("changing the parent's owner needs root")
	}
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	t.Setenv("XDG_RUNTIME_DIR", "")
	parent := filepath.Join(os.TempDir(), fmt.Sprintf("sb-%d", os.Getuid()))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := SessionsDir(); err == nil || !strings.Contains(err.Error(), "not this user's (uid 1)") {
		t.Fatalf("SessionsDir() with another user's parent: %v; want a refusal", err)
	}
}

// TestSessionsDirRefusesASymlinkParent covers the fallback's parent: a
// <tmp>/sb-<uid> symlink pointing at this user's own 0700 directory —
// everything the verification asks for — is refused anyway: the path
// itself must be the directory, not a link to one, whoever owns the
// link can replace it afterwards.
func TestSessionsDirRefusesASymlinkParent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	t.Setenv("XDG_RUNTIME_DIR", "")
	parent := filepath.Join(os.TempDir(), fmt.Sprintf("sb-%d", os.Getuid()))
	// The link's target is this user's, 0700: everything sb would
	// verify — the mode check below must not fire before the link
	// check, whatever a plain Stat would adopt.
	target := t.TempDir()
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := SessionsDir(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("SessionsDir() with a symlinked parent: %v; want a refusal", err)
	}
}

// TestNewSessionNameGeneratesUniqueNames covers the generator: two calls
// give two names, each the shape a user can type into sb exec --name.
func TestNewSessionNameGeneratesUniqueNames(t *testing.T) {
	first, second := NewSessionName(), NewSessionName()
	if first == second {
		t.Fatalf("NewSessionName() twice: %q both times", first)
	}
	for _, name := range []string{first, second} {
		if !strings.HasPrefix(name, "sb-") || len(name) != len("sb-")+16 {
			t.Fatalf("NewSessionName() = %q; want sb- + 16 hex", name)
		}
	}
}

// TestAcquireRefusesAnUnreadableRecord covers the record's readability: a
// record that cannot be read (corrupt json) is not the same as no record —
// the name is not free while the record is there, whatever a reuse would
// need the record for.
func TestAcquireRefusesAnUnreadableRecord(t *testing.T) {
	dir := testSessionsDir(t)
	if err := os.WriteFile(RecordPath(dir, "default"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir, "default"); err == nil || !strings.Contains(err.Error(), "read session record") {
		t.Fatalf("Acquire() with a corrupt record: %v; want a refusal", err)
	}
}

// TestReclaimErrorAdvisesPerRuntime covers the recovery advice: each
// runtime's listing is what the advice says for it — the apple CLI lists
// as JSON, docker and podman by label — and the advice names the
// runtime's own binary without looking for it on PATH: whatever picks
// the ids out of the listing by hand works without the CLI too.
func TestReclaimErrorAdvisesPerRuntime(t *testing.T) {
	issue := "/issue"
	appleErr := ReclaimError(Record{Name: "dev", ID: "sid", Runtime: "apple", IssueDir: issue}, "records")
	if !strings.Contains(appleErr.Error(), "container ls --all --format json") {
		t.Fatalf("ReclaimError(apple) = %v; want the apple listing", appleErr)
	}
	if strings.Contains(appleErr.Error(), "ps -aq --filter") {
		t.Fatalf("ReclaimError(apple) = %v; advises the docker/podman listing", appleErr)
	}
	// The listing mixes this session's containers with other sessions'
	// and sb-less ones: what to remove is picked out of it by hand —
	// only the ids whose labels carry the session — never everything
	// the listing lists.
	if !strings.Contains(appleErr.Error(), "pick the ids whose labels carry sb.session.id=sid — only those") {
		t.Fatalf("ReclaimError(apple) = %v; want the pick line", appleErr)
	}
	if !strings.Contains(appleErr.Error(), "container rm -f <the ids picked above>") {
		t.Fatalf("ReclaimError(apple) = %v; want the picked ids' removal", appleErr)
	}
	if strings.Contains(appleErr.Error(), "apple ps") {
		t.Fatalf("ReclaimError(apple) = %v; advises the missing apple binary", appleErr)
	}
	// Docker and podman list by label: nothing to pick out of them.
	dockerErr := ReclaimError(Record{Name: "dev", ID: "sid", Runtime: "docker", IssueDir: issue}, "records")
	if !strings.Contains(dockerErr.Error(), "docker ps -aq --filter label=sb.session.id=sid") {
		t.Fatalf("ReclaimError(docker) = %v; want the ps --filter listing", dockerErr)
	}
	if strings.Contains(dockerErr.Error(), "pick the ids") {
		t.Fatalf("ReclaimError(docker) = %v; advises picking out of a filtered listing", dockerErr)
	}
	if !strings.Contains(dockerErr.Error(), "docker rm -f <the ids it lists>") {
		t.Fatalf("ReclaimError(docker) = %v; want the listed ids' removal", dockerErr)
	}
}
