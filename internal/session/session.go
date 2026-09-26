// Package session owns sb session records: one file per session under a
// per-boot directory (XDG_RUNTIME_DIR), locked by the session owner for the
// session's lifetime. The lock is the owner's claim on the session name: as
// long as it is held, the session is alive and its containers are sb's to
// stop and remove; a session whose lock can be taken is an orphan and is
// reclaimed at the next sb startup.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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

// baseDir returns sb's per-boot base directory under XDG_RUNTIME_DIR (or
// the temp dir when unset or relative), creating it with 0700.
func baseDir() (string, error) {
	dir := os.TempDir()
	if runtime, ok := os.LookupEnv("XDG_RUNTIME_DIR"); ok && filepath.IsAbs(runtime) {
		dir = filepath.Join(runtime, "sb")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

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

// Acquire takes the named session's lock for this process, refusing when a
// live session holds it. The lock is held until DeleteRecord releases it.
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
	return &Lock{f: f, path: path}, nil
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
	return &Lock{f: f, path: path}, nil
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
	f    *os.File
	path string
}

// DeleteRecord deletes the record and lock files and releases the lock.
// Called on the stop path, it must succeed even when the container was
// already removed by the runtime.
func (l *Lock) DeleteRecord(dir, name string) error {
	if l == nil || l.f == nil {
		return nil
	}
	recordErr := os.Remove(RecordPath(dir, name))
	lockErr := os.Remove(l.path)
	l.Release()
	if (recordErr != nil && !errors.Is(recordErr, fs.ErrNotExist)) ||
		(lockErr != nil && !errors.Is(lockErr, fs.ErrNotExist)) {
		return fmt.Errorf("delete session files: record: %v, lock: %v", recordErr, lockErr)
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
		if err := sweepSession(dir, name, lock); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sweepSession reclaims one orphaned session. On any failure the caller
// retries the whole session next sweep, so the lock is only released here.
func sweepSession(dir, name string, lock *Lock) error {
	defer lock.Release()
	rec, err := LoadRecord(dir, name)
	if err != nil {
		return fmt.Errorf("sweep %s: %w", name, err)
	}
	rt, err := containers.Parse(rec.Runtime)
	if err == nil {
		err = containers.RemoveSession(rt, rec.ID)
	}
	if err != nil {
		return fmt.Errorf("sweep %s: remove containers: %w", name, err)
	}
	if rec.IssueDir != "" {
		if err := os.RemoveAll(rec.IssueDir); err != nil {
			return fmt.Errorf("sweep %s: remove issue dir: %w", name, err)
		}
	}
	if err := lock.DeleteRecord(dir, name); err != nil {
		return fmt.Errorf("sweep %s: %w", name, err)
	}
	return nil
}
