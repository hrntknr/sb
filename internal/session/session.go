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
}

// baseDir returns sb's per-boot base directory. With XDG_RUNTIME_DIR it is
// <XDG_RUNTIME_DIR>/sb; without it a per-uid directory under the temp dir
// (<tmp>/sb-<uid>/sb) keeps users apart. The existing directory must be
// this user's and 0700: a directory another user created (or a wider
// mode) is refused, not adopted.
func baseDir() (string, error) {
	var dir string
	if runtime, ok := os.LookupEnv("XDG_RUNTIME_DIR"); ok && filepath.IsAbs(runtime) {
		dir = filepath.Join(runtime, "sb")
	} else {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("sb-%d", uid()), "sb")
	}
	if err := secureMkdir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// secureMkdir creates dir 0700 and verifies what is already there: the
// directory must be this user's and 0700 before sb writes into it.
func secureMkdir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
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
// name may not be reused until they are gone by hand.
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
	if rec, err := LoadRecord(dir, name); err == nil {
		f.Close()
		return nil, ReclaimError(rec, dir)
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
		if err := StopSession(dir, name, lock); err != nil {
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
func StopSession(dir, name string, lock *Lock) error {
	defer lock.Release()
	rec, err := LoadRecord(dir, name)
	if err != nil {
		return ReclaimError(Record{Name: name}, dir)
	}
	if err := removeContainers(&rec); err != nil {
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
// not answer within it is killed, and the removal is a failed one.
func removeContainers(rec *Record) error {
	rt, err := containers.Parse(rec.Runtime)
	if err != nil {
		return err
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
	if rt, err := containers.Parse(rec.Runtime); err == nil {
		binary = rt.Binary()
	}
	return fmt.Errorf("session %q: containers left behind by a failed removal\n"+
		"(runtime %s, session id %s, container id %q);\n"+
		"reclaim them by hand, then start again:\n"+
		"  %s ps -aq --filter label=%s=%s\n"+
		"  %s rm -f <the ids it lists>\n"+
		"  rm -rf %s\n"+
		"  rm %s",
		rec.Name, binary, rec.ID, rec.ContainerID,
		binary, containers.LabelSession, rec.ID,
		binary, rec.IssueDir, RecordPath(dir, rec.Name))
}
