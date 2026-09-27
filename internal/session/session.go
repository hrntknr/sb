// Package session owns sb session records: one file per session under a
// persistent per-owner state directory (XDG_STATE_HOME), locked by the
// session owner for the session's lifetime. The lock is the owner's claim
// on the session name: as long as it is held, the session is alive and its
// containers are sb's to stop and remove; a session whose lock can be taken
// is an orphan and is reclaimed at the next sb startup. The records and
// locks persist across host restarts: the runtime directory does not, so
// what survives a restart to find the containers (stopped but not gone) has
// to live where the restart cannot wipe it.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrntknr/sb/internal/containers"
	"github.com/hrntknr/sb/internal/util"
	"golang.org/x/sys/unix"
)

// Record is the on-disk session record. The session ID labels the session's
// containers; ContainerID is what the runtime wrote in the cidfile,
// recorded once the container exists.
type Record struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	Runtime     string `json:"runtime"`
	IssueDir    string `json:"issueDir"`
	ContainerID string `json:"containerId,omitempty"`
	// CreationSettled persists whether the container creation's result
	// is fixed. False — what a sweep reads — means the runtime may
	// still commit the container: the CLI is still running, or was
	// killed mid-flight, or exited with the daemon's own result
	// unknown. A sweep may not settle the creation on an empty
	// listing: it could not tell a creation still in flight from one
	// that will never commit, so the record stays until a removal
	// could confirm its end (a listing that found the session's
	// containers) — or until it is reclaimed by hand.
	CreationSettled bool `json:"creationSettled"`
}

// baseDir returns sb's per-boot base directory: the runtime directory.
// With XDG_RUNTIME_DIR it is <XDG_RUNTIME_DIR>/sb; without it a per-uid
// directory under the temp dir (<tmp>/sb-<uid>/sb) keeps users apart. The
// temp root is shared — anyone may leave anything under it — so every
// directory sb puts there is verified: this user's, 0700, and a real
// directory; a symlink is its owner's, not sb's, and is refused, not
// adopted. This directory is wiped by a host restart; what must survive
// one (the records, the locks) lives in the state directory instead.
func baseDir() (string, error) {
	var dir string
	if runtime, ok := os.LookupEnv("XDG_RUNTIME_DIR"); ok && filepath.IsAbs(runtime) {
		dir = filepath.Join(runtime, "sb")
		if err := secureMkdir(dir); err != nil {
			return "", err
		}
	} else {
		// The fallback's per-uid directory is created and verified first: another
		// user claiming <tmp>/sb-<uid> must not carry sb's subtree.
		parent := filepath.Join(os.TempDir(), fmt.Sprintf("sb-%d", uid()))
		if err := secureMkdir(parent); err != nil {
			return "", err
		}
		dir = filepath.Join(parent, "sb")
		if err := secureMkdir(dir); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// stateBaseDir returns sb's persistent base directory: the state directory,
// where the session records and locks live. With XDG_STATE_HOME it is
// <XDG_STATE_HOME>/sb; without it $HOME/.local/state/sb. Unlike the runtime
// directory it survives a host restart: a stopped container outlives the
// sb that created it, and the record is what finds its containers again
// after the restart.
//
// The tree sb's own calls may have built holds every level from the
// first existing one down to the sb dir — the state home itself, or
// .local and state under the home — and each one's entry is what the
// creation persists and every call confirms: a call that left a level
// behind without its sync does not have the next one skip it.
func stateBaseDir() (string, error) {
	var dir string
	if state, ok := os.LookupEnv("XDG_STATE_HOME"); ok && filepath.IsAbs(state) {
		dir = filepath.Join(state, "sb")
		if err := secureMkdir(dir); err != nil {
			return "", fmt.Errorf("state dir %s: %w", dir, err)
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("state dir: %w", err)
		}
		dir = filepath.Join(home, ".local", "state", "sb")
		if err := secureMkdir(dir); err != nil {
			return "", fmt.Errorf("state dir %s: %w", dir, err)
		}
	}
	return dir, nil
}

// secureMkdir establishes dir as sb's own — created 0700 with the
// levels above it that do not exist yet, verified: the path must be
// this user's real directory 0700 before sb writes into it. The
// verification is on the path itself, not what it points at: a
// symlink there is its owner's, not sb's, and whoever owns it can
// replace it afterwards.
//
// The creation goes one directory at a time, shallowest first, and each
// creation's entry in its parent is synced to the disk before the next
// one: without that, a host failure right after a creation could lose
// the entry — the whole tree sb is about to build under it — while
// the process that made it was told it succeeded. A sync that fails
// stops the creation: the caller gets the failure, not a tree that
// might not be there.
//
// Then every level of the same tree — the first existing ancestor
// included, existing or not, created by this call or left by a failed
// one — gets its entry synced after the creation: what sb might have
// built is not its existence but its persistence that the next call
// needs, and a level that exists is not thereby one whose entry is on
// the disk. So the tree is returned as usable only when every entry
// that names it is on the disk — on every call, not only at the
// creation that happens to be this one. What is above the first
// existing ancestor existed before sb: its entry is not sb's to
// persist, and none of its own creation either.
func secureMkdir(dir string) error {
	levels, err := missingDirs(dir)
	if err != nil {
		return err
	}
	for _, p := range levels {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
		if err := syncDirEntry(filepath.Dir(p)); err != nil {
			return err
		}
	}
	for _, p := range levels {
		if err := syncDirEntry(filepath.Dir(p)); err != nil {
			return err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("session dir %s: not a directory", dir)
	}
	owner, ok := ownerOf(info)
	if !ok || owner != uid() {
		return fmt.Errorf("session dir %s: not this user's (uid %d)", dir, owner)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("session dir %s: mode is %o, want 0700", dir, info.Mode().Perm())
	}
	return nil
}

// missingDirs lists the levels of the tree that holds dir, shallowest
// first: the walk goes up from dir and stops at the first existing
// level — what is above it existed before sb and is neither sb's to
// create nor sb's to persist — and that level is the tree's top:
// the levels from it down to dir are the ones sb's own calls may have
// built, existing or not, created by an earlier call or left by a
// failed one. What is missing among them is secureMkdir's to create;
// every one of them is its to persist.
func missingDirs(dir string) ([]string, error) {
	var deepest []string // deepest first as walked up
	for d := dir; ; {
		if _, err := os.Lstat(d); err == nil {
			// The first existing level: it is the tree's top.
			deepest = append(deepest, d)
			break
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		deepest = append(deepest, d)
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	shallow := make([]string, len(deepest))
	for i, d := range deepest {
		shallow[len(deepest)-1-i] = d
	}
	return shallow, nil
}

// syncDirEntry syncs a directory's entries to what the disk holds, and
// is the seam the tests hook: a sync that fails is what the tests make
// happen, checking the creation stops there and the caller gets the
// failure. It is the directory the entry was added to that is synced:
// the child is on the disk by the mkdir, what is not yet is the parent's
// record of it.
var syncDirEntry = func(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// ownerOf returns the uid owning info's path; ok is false where the
// owner cannot be read.
func ownerOf(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// uid is this process's uid.
func uid() uint32 { return uint32(os.Getuid()) }

// SessionsDir returns the directory holding the session records and locks,
// creating it with 0700. It lives in the persistent state directory: a host
// restart wipes the runtime directory, but the records and locks outlive it
// there, so the next startup still finds what a restart left behind.
func SessionsDir() (string, error) {
	dir, err := stateBaseDir()
	if err != nil {
		return "", err
	}
	sessions := filepath.Join(dir, "sessions")
	if err := secureMkdir(sessions); err != nil {
		return "", err
	}
	return sessions, nil
}

// NewIssueDir creates the session's issue directory — where the session's
// credentials are written — named after the session ID, with 0700. It
// lives in the runtime directory: the credentials are live-session
// material, not something a restart or the next startup needs.
func NewIssueDir(sessionID string) (string, error) {
	dir, err := baseDir()
	if err != nil {
		return "", err
	}
	issue := filepath.Join(dir, "issues", sessionID)
	if err := secureMkdir(issue); err != nil {
		return "", err
	}
	return issue, nil
}

// RecordPath returns the path of the named session's record file.
func RecordPath(dir, name string) string { return filepath.Join(dir, name+".json") }

// LockPath returns the path of the named session's lock file.
func LockPath(dir, name string) string { return filepath.Join(dir, name+".lock") }

// SaveRecord atomically writes the record.
func SaveRecord(dir string, rec Record) error {
	content, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return util.WriteFileAtomic(RecordPath(dir, rec.Name), 0o600, content)
}

// LoadRecord reads the named session's record.
func LoadRecord(dir, name string) (Record, error) {
	content, err := os.ReadFile(RecordPath(dir, name))
	if err != nil {
		return Record{}, fmt.Errorf("read session record: %w", err)
	}
	var rec Record
	if err := json.Unmarshal(content, &rec); err != nil {
		return Record{}, fmt.Errorf("read session record: %w", err)
	}
	return rec, nil
}

// NewSessionID returns a random session ID for the container label.
func NewSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// NewSessionName returns a random session name for a run whose --name was
// omitted: random enough that a second run does not collide with the
// first, short enough to type into sb exec.
func NewSessionName() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "sb-" + hex.EncodeToString(b[:])
}

// Acquire takes the named session's lock for this process. It refuses
// when a live session holds it, and — once the lock is taken — when the
// name still has a record from a removal that failed: that record is
// what the next removal needs, and its containers are unreclaimed; the
// name may not be reused until they are gone by hand. A record that
// cannot be read at all (corrupt, unreadable) is not the same as no
// record: it is refused too, as what the retry needs is in it.
func Acquire(dir, name string) (*Lock, error) {
	path := LockPath(dir, name)
	f, err := openLockFile(path, true)
	if err != nil {
		return nil, fmt.Errorf("open session lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("session %q is already running", name)
	}
	rec, err := LoadRecord(dir, name)
	switch {
	case err == nil:
		f.Close()
		// The lock is this process's, but the name is not: its
		// containers are unreclaimed and the record is what the
		// removal needs.
		return nil, ReclaimError(rec, dir)
	case errors.Is(err, fs.ErrNotExist):
		// No record: the name is free.
	default:
		f.Close()
		return nil, fmt.Errorf("acquire %q: %w", name, err)
	}
	return &Lock{f: f}, nil
}

// LockHeld reports whether a live session holds the named session's lock.
// It never takes the lock itself, so it cannot disturb the owner.
func LockHeld(dir, name string) bool {
	f, err := openLockFile(LockPath(dir, name), false)
	if err != nil {
		return false
	}
	held := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil
	f.Close()
	return held
}

// tryLock takes the named session's lock non-blockingly. A nil Lock with a
// nil error means a live session holds it.
func tryLock(dir, name string) (*Lock, error) {
	path := LockPath(dir, name)
	f, err := openLockFile(path, true)
	if err != nil {
		return nil, fmt.Errorf("open session lock %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, nil
	}
	return &Lock{f: f}, nil
}

// openLockFile opens a session lock file. O_CLOEXEC matters: the runtime CLI
// child must not inherit the session lock, or a killed sb would leave the
// lock held by the CLI process it spawned.
func openLockFile(path string, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT
	}
	return os.OpenFile(path, int(flags), 0o600)
}

// Lock is a held session lock.
type Lock struct {
	f *os.File
}

// DeleteRecord deletes the record file and releases the lock. The lock
// file stays: deleting it would let two processes hold different inodes
// of the same name (one with the file already open, one over a freshly
// created path) and break the name's exclusivity — the file is the
// name's stable claim, the lock on it is the current owner's.
func (l *Lock) DeleteRecord(dir, name string) error {
	if l == nil || l.f == nil {
		return nil
	}
	recordErr := os.Remove(RecordPath(dir, name))
	l.Release()
	if recordErr != nil && !errors.Is(recordErr, fs.ErrNotExist) {
		return fmt.Errorf("delete session record %s: %w", RecordPath(dir, name), recordErr)
	}
	return nil
}

// Release drops the lock without touching the files.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	l.f.Close()
	l.f = nil
}

// Sweep reclaims orphaned sessions: every session whose lock can be taken
// non-blockingly is an orphan (its owner is gone), so its containers are
// stopped and removed by the session ID label, its issue directory is
// deleted, and its record and lock file are removed. A live session (lock
// held) is left alone. A session whose containers could not be removed keeps
// its record so the next sweep retries.
//
// What the record itself says decides how far the sweep may go: a record
// whose creation is not settled may not be dropped on an empty listing —
// the runtime could still commit the container, and nothing else could find
// it — so the sweep keeps it, and the removal's own listing confirms the
// creation's end when it can.
func Sweep(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		lock, err := tryLock(dir, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if lock == nil {
			continue // a live session holds it
		}
		rec, err := LoadRecord(dir, name)
		if err != nil {
			// A record that cannot be read cannot be settled
			// either: it stays, and the next sweep retries
			// with it. Nothing of sb holds the name.
			lock.Release()
			errs = append(errs, fmt.Errorf("sweep %q: read record: %w", name, err))
			continue
		}
		if err := StopSession(dir, name, lock, true, rec.CreationSettled); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// StopSession stops one session — a running one (its owner stopped it) or
// an orphan (the sweep found it). Its containers are removed by the session
// label, the issue dir is deleted, then the record; whatever it is that
// fails keeps what the retry needs — the record stays — and releases the
// lock either way: after this, nothing of sb holds the name.
//
// What may still be committed decides whether the record may be dropped:
// the issuing tasks still writing (issuanceExited false), or the creation's
// result still unknown AND this removal's own listing found nothing of it
// (creationSettled false, found false) — the container could still be
// committed after the removal, so nothing may be settled on the empty
// listing. What this listing found — the session's containers, the only
// things the creation could have committed — confirms the creation's end:
// one create commits exactly one container, so nothing of it appears after
// the removal of what it committed.
func StopSession(dir, name string, lock *Lock, issuanceExited, creationSettled bool) error {
	defer lock.Release()
	rec, err := LoadRecord(dir, name)
	if err != nil {
		return ReclaimError(Record{Name: name}, dir)
	}
	found, err := settleAndRemove(dir, &rec)
	if err != nil {
		return ReclaimError(rec, dir)
	}
	if !issuanceExited || !(creationSettled || found) {
		// The issuing tasks are still writing the issue dir, or the
		// creation's result is still unknown and this removal could
		// not confirm its end. What the removal lists is not the
		// whole truth yet. The record stays; the next sweep retries
		// with it.
		return ReclaimError(rec, dir)
	}
	if rec.IssueDir != "" {
		if err := os.RemoveAll(rec.IssueDir); err != nil {
			return ReclaimError(rec, dir)
		}
	}
	if err := lock.DeleteRecord(dir, name); err != nil {
		return ReclaimError(rec, dir)
	}
	return nil
}

// settleAndRemove removes the session's containers by label and settles
// the creation with what the removal observes. The listing finds the
// containers the creation committed — that observation is the evidence
// the creation settled — and the destruction runs only after the
// settlement is on the disk: whatever the record says, it goes out
// again before a single container is destroyed. A save whose sync
// failed after the rename left the settlement visible at the final
// name without being on the disk: read back as done, it would have
// the next stop or skip the save and destroy on what survived no stop —
// so the save is not skipped, whatever the record says, and the removal
// proceeds only after a successful one.
func settleAndRemove(dir string, rec *Record) (found bool, err error) {
	rt, err := containers.ParseName(rec.Runtime)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), RuntimeWait)
	defer cancel()
	ids, err := containers.ListSession(ctx, rt, rec.ID)
	if err != nil {
		return false, err
	}
	found = len(ids) > 0
	if found {
		// The creation's committed containers are in hand: the
		// creation cannot commit anything else (one create commits
		// exactly one container). The evidence goes out before the
		// destruction — persist it now, and only a successful
		// save lets the destruction run on it.
		rec.CreationSettled = true
		if err := SaveRecord(dir, *rec); err != nil {
			return found, err
		}
	}
	return found, containers.RemoveListed(ctx, rt, rec.ID, ids)
}

// RuntimeWait bounds each runtime CLI call a session's stop or check
// makes: listing by label, removing by id, verifying a container. A
// runtime that does not answer within it is killed, and the call is a
// failed one.
const RuntimeWait = 5 * time.Second

// ReclaimError explains a session whose stop did not finish: what is left
// behind, and what to run by hand before the name may be used again. The
// record stays so the next sweep retries with it.
//
// What the record itself says decides the advice. A settled creation's
// containers are all it committed: removing them by hand is safe, and the
// record follows. A creation whose result is still unknown may still be
// committing this session's container — an empty listing does not settle
// it, and a record deleted on one would leave a late commit unclaimed — so
// the next sweep retries with this record, and the by-hand reclaim runs
// only after the creation request has ended.
func ReclaimError(rec Record, dir string) error {
	binary := rec.Runtime
	var runtime containers.Runtime
	if rt, err := containers.ParseName(rec.Runtime); err == nil {
		runtime, binary = rt, rt.Binary()
	}
	list, pick, rm := listingCommands(binary, runtime, rec)
	header := fmt.Sprintf("session %q: creation's result still unknown after a failed stop\n"+
		"(runtime %s, session id %s);\n"+
		"the runtime may still be committing this session's container, so the\n"+
		"next sweep retries with this record. To reclaim by hand, confirm the\n"+
		"creation request has ended first — nothing is still creating this\n"+
		"container — then run, with nothing left to commit:\n",
		rec.Name, binary, rec.ID)
	if rec.CreationSettled {
		header = fmt.Sprintf("session %q: containers left behind by a failed removal\n"+
			"(runtime %s, session id %s, container id %q);\n"+
			"the creation's result is fixed: nothing is still being committed.\n"+
			"reclaim them by hand, then start again:\n",
			rec.Name, binary, rec.ID, rec.ContainerID)
	}
	return fmt.Errorf("%s"+
		"  %s\n%s"+
		"  %s rm -f %s\n"+
		"  rm -rf %s\n"+
		"  rm %s",
		header,
		list, pick,
		binary, rm,
		rec.IssueDir, RecordPath(dir, rec.Name))
}

// listingCommands builds the by-label listing the by-hand reclaim starts
// from, and the id argument its removal takes: each runtime's own way of
// naming what this session left behind. binary is the runtime's executable
// (the apple CLI is "container", the rest run under their own names).
func listingCommands(binary string, runtime containers.Runtime, rec Record) (list, pick, rm string) {
	list = fmt.Sprintf("%s ps -aq --filter label=%s=%s", binary, containers.LabelSession, rec.ID)
	rm = "<the ids it lists>"
	if runtime == containers.Apple {
		// The apple CLI lists everything as JSON: what this session
		// left behind is picked out of it by hand — only the
		// containers carrying the session label; the rest belong to
		// other sessions, or to no sb at all.
		list = fmt.Sprintf("%s ls --all --format json", binary)
		pick = fmt.Sprintf("  # pick the ids whose labels carry %s=%s — only those\n", containers.LabelSession, rec.ID)
		rm = "<the ids picked above>"
	}
	return list, pick, rm
}
