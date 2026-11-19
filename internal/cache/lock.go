package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// LockRoot is the directory that holds per-user lock directories.
func LockRoot() string {
	if runtime.GOOS == "linux" {
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			return dir
		}
		return fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	return os.TempDir()
}

// PrivateDir creates dir if needed and checks that it is a real directory
// (not a symlink) owned by the current user and closed to everyone else.
func PrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be a directory owned by the current user with mode 0700", dir)
	}
	return nil
}

// Lock serialises cache access for harness so that concurrent invocations
// prompt only once. The lock file is empty and never holds a secret.
func Lock(harness string) (func(), error) {
	return LockIn(LockRoot(), harness)
}

// LockIn is Lock with an explicit root directory.
func LockIn(root, harness string) (func(), error) {
	dir := filepath.Join(root, fmt.Sprintf("harness-root-hook-locks-%d", os.Getuid()))
	if err := PrivateDir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, harness), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
