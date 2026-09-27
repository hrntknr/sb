package util

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config")
	if err := WriteFileAtomic(path, 0o600, []byte("content")); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "content" {
		t.Fatalf("content = %q, want %q", content, "content")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestWriteFileAtomicResetsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := WriteFileAtomic(path, 0o600, []byte("new")); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600 after rewrite", info.Mode().Perm())
	}
}

// Regression: a downstream process must not be able to make the proxy write
// through a symlink it installed at the output path.
func TestWriteFileAtomicReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("victim"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	path := filepath.Join(dir, "config")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	if err := WriteFileAtomic(path, 0o600, []byte("new")); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("path is still a symlink after write")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "new" {
		t.Fatalf("content = %q, want %q", content, "new")
	}
	victim, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target) error = %v", err)
	}
	if string(victim) != "victim" {
		t.Fatalf("symlink target was modified: %q", victim)
	}
}

// Regression: a downstream process must not be able to make the proxy write
// into a symlinked output directory.
func TestWriteFileAtomicRejectsSymlinkedDir(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "out")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	if err := WriteFileAtomic(filepath.Join(link, "config"), 0o600, []byte("x")); err == nil {
		t.Fatal("WriteFileAtomic() through symlinked dir should fail")
	}
	if _, err := os.Stat(filepath.Join(real, "config")); !os.IsNotExist(err) {
		t.Fatal("write escaped through symlinked dir")
	}
}

// TestWriteFileAtomicSyncsAfterTheRename pins the write's order: the
// file's content is synced inside the temp file, the rename puts it at
// the final name, and the directory's entry for it is synced after the
// rename — the write is not successful until the entry is on disk. The
// hook observes the moment between the rename and the sync: if the sync
// came before the rename, the final name would hold nothing yet (a first
// write) or the previous content (a rewrite), and the sync would have
// nothing to flush for the caller that comes after it.
func TestWriteFileAtomicSyncsAfterTheRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}
	real := SyncDir
	defer func() { SyncDir = real }()
	SyncDir = func(dirfd int) error {
		// At the sync the rename already happened: the entry is at
		// the final name and its content is the new one. Before the
		// rename the name held the previous content — a sync there
		// would flush the old entry and nothing else.
		content, err := os.ReadFile(path)
		if err != nil || string(content) != "content" {
			t.Errorf("the sync ran before the rename: %v %q", err, content)
		}
		return real(dirfd)
	}
	if err := WriteFileAtomic(path, 0o600, []byte("content")); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
}

// TestWriteFileAtomicFailsWhenTheSyncDoes covers the failure the sync
// carries: a directory that cannot be synced makes the write fail with
// that failure, after the rename — the file is at the final name (the
// rename went through), but the caller is not told the write succeeded.
// Without the sync in the success condition, the failure would be
// silenced: the write would return nil, and a host failure right after
// it could lose the entry — the file exists, the entry does not.
func TestWriteFileAtomicFailsWhenTheSyncDoes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	real := SyncDir
	defer func() { SyncDir = real }()
	SyncDir = func(dirfd int) error { return errSyncFailed }
	if err := WriteFileAtomic(path, 0o600, []byte("content")); err == nil || !errors.Is(err, errSyncFailed) {
		t.Fatalf("WriteFileAtomic() = %v, want the sync's failure", err)
	}
	// The rename went through before the sync failed: the file is at
	// the final name. The write failed anyway — the caller may not
	// treat a half-rename as a success.
	if content, err := os.ReadFile(path); err != nil || string(content) != "content" {
		t.Fatalf("the file after the failed write: %v %q", err, content)
	}
}

// errSyncFailed is the failure the tests inject into the sync.
var errSyncFailed = errors.New("sync failed for the test")
