package util

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// WriteFileAtomic replaces path with content via a temporary file followed by
// a rename. The output directory is opened once with O_NOFOLLOW and every
// file operation is done relative to that directory descriptor, so a process
// that can modify the output directory by path cannot redirect the write
// through a symlink between the steps. A symlink installed at the
// destination is replaced by the rename, and the mode is always reset.
func WriteFileAtomic(path string, mode os.FileMode, content []byte) error {
	dir, base := filepath.Dir(path), filepath.Base(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dirfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	defer unix.Close(dirfd)

	name, err := writeTempFile(dirfd, base, mode, content)
	if err != nil {
		return err
	}
	// After a successful rename the temp name no longer exists, so this
	// only cleans up on failure.
	defer func() { _ = unix.Unlinkat(dirfd, name, 0) }()
	if err := unix.Renameat(dirfd, name, dirfd, base); err != nil {
		return fmt.Errorf("rename %s: %w", base, err)
	}
	return nil
}

// writeTempFile creates an exclusive temporary file relative to dirfd,
// writes content, and returns its name.
func writeTempFile(dirfd int, base string, mode os.FileMode, content []byte) (string, error) {
	for {
		suffix, err := randomSuffix()
		if err != nil {
			return "", err
		}
		name := "." + base + "." + suffix
		fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, uint32(mode.Perm()))
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("create temp file: %w", err)
		}
		if err := writeAll(os.NewFile(uintptr(fd), name), mode, content); err != nil {
			_ = unix.Unlinkat(dirfd, name, 0)
			return "", err
		}
		return name, nil
	}
}

func writeAll(f *os.File, mode os.FileMode, content []byte) error {
	_, err := f.Write(content)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func randomSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
