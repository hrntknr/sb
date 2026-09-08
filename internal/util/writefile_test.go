package util

import (
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
