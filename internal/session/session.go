// Package session owns sb session records: one file per session under a
// per-boot directory (XDG_RUNTIME_DIR), locked by the session owner for the
// session's lifetime. The lock is the owner's claim on the session name: as
// long as it is held, the session is alive and its containers are sb's to
// stop and remove; a session whose lock can be taken is an orphan and is
// reclaimed at the next sb startup.
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

// baseDir returns sb's per-boot base directory. With XDG_RUNTIME_DIR it is
// <XDG_RUNTIME_DIR>/sb; without it a per-uid directory under the temp dir
// (<tmp>/sb-<uid>/sb) keeps users apart. The temp root is shared — anyone
// may leave anything under it — so every directory sb puts there is
// verified: this user's, 0700, and a real directory; a symlink is its
// owner's, not sb's, and is refused, not adopted.
func baseDir() (string, error) {
	var dir string
	if runtime, ok := os.LookupEnv("XDG_RUNTIME_DIR"); ok && filepath.IsAbs(runtime) {
		dir = filepath.Join(runtime, "sb")
	} else {
		// The fallback's parent is created and verified first: another
		// user claiming <tmp>/sb-<uid> must not carry sb's subtree.
		parent := filepath.Join(os.TempDir(), fmt.Sprintf("sb-%d", uid()))
		if err := secureMkdir(parent); err != nil {
			return "", err
		}
		dir = filepath.Join(parent, "sb")
	}
	if err := secureMkdir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// secureMkdir creates dir 0700 and verifies what is already there: the
// path must be this user's real directory 0700 before sb writes into it.
// The verification is on the path itself, not what it points at: a
// symlink there is its owner's, not sb's, and whoever owns it can
// replace it afterwards.
func secureMkdir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
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
// creating it with 0700.
func SessionsDir() (string, error) {
	dir, err := baseDir()
	if err != nil {
		return "", err
	}
	sessions := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		return "", err
	}
	return sessions, nil
}

// NewIssueDir creates the session's issue directory — where the session's
// credentials are written — named after the session ID, with 0700.
func NewIssueDir(sessionID string) (string, error) {
	dir, err := baseDir()
	if err != nil {
		return "", err
	}
	issue := filepath.Join(dir, "issues", sessionID)
	if err := os.MkdirAll(issue, 0o700); err != nil {
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
	found, err := removeContainers(&rec)
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

// removeContainers stops and removes the record's containers by session
// label. Each runtime call is bounded by RuntimeWait: a runtime that does
// not answer within it is killed, and the removal is a failed one. found
// reports whether the listing saw any container of the session.
func removeContainers(rec *Record) (found bool, err error) {
	rt, err := containers.ParseName(rec.Runtime)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), RuntimeWait)
	defer cancel()
	return containers.RemoveSession(ctx, rt, rec.ID)
}

// RuntimeWait bounds each runtime CLI call a session's stop or check
// makes: listing by label, removing by id, verifying a container. A
// runtime that does not answer within it is killed, and the call is a
// failed one.
const RuntimeWait = 5 * time.Second

// ReclaimError explains a session whose stop did not finish: what is left
// behind, and what to run by hand before the name may be used again. The
// record stays so the next sweep retries with it.
func ReclaimError(rec Record, dir string) error {
	binary := rec.Runtime
	var runtime containers.Runtime
	if rt, err := containers.ParseName(rec.Runtime); err == nil {
		runtime, binary = rt, rt.Binary()
	}
	list := fmt.Sprintf("%s ps -aq --filter label=%s=%s", binary, containers.LabelSession, rec.ID)
	rm := "<the ids it lists>"
	pick := ""
	if runtime == containers.Apple {
		// The apple CLI lists everything as JSON: what this session
		// left behind is picked out of it by hand — only the
		// containers carrying the session label; the rest belong to
		// other sessions, or to no sb at all.
		list = fmt.Sprintf("%s ls --all --format json", binary)
		pick = fmt.Sprintf("  # pick the ids whose labels carry %s=%s — only those\n", containers.LabelSession, rec.ID)
		rm = "<the ids picked above>"
	}
	return fmt.Errorf("session %q: containers left behind by a failed removal\n"+
		"(runtime %s, session id %s, container id %q);\n"+
		"reclaim them by hand, then start again:\n"+
		"  %s\n%s"+
		"  %s rm -f %s\n"+
		"  rm -rf %s\n"+
		"  rm %s",
		rec.Name, binary, rec.ID, rec.ContainerID,
		list, pick,
		binary, rm,
		rec.IssueDir, RecordPath(dir, rec.Name))
}
