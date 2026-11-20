package cache

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
)

// Store is an OS credential-store entry for one harness.
type Store interface {
	// Metadata returns non-secret timestamps, or nil when there is no entry.
	Metadata() (*Meta, error)
	// Load returns the full record, or nil when missing or malformed.
	Load() (*Record, error)
	Save(Record) error
	Clear() error
}

// ErrUnsupported is returned on operating systems other than macOS and Linux.
var ErrUnsupported = errors.New("only Linux and macOS are supported")

// Account is the current user's login name.
func Account() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// Home is the current user's home directory from the account database. Unlike
// os.UserHomeDir it does not follow $HOME, which the caller of psudo controls.
// (A pure-Go Linux build reads /etc/passwd; for an account that is not listed
// there, such as one from LDAP, the lookup itself falls back to $HOME.)
func Home() string {
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	home, _ := os.UserHomeDir()
	return home
}

// Identity sets HOME, USER and LOGNAME in env to the values from the account
// database, replacing whatever the caller put there. A program started with
// env then reads its dotfiles from the real home directory, not from a folder
// the caller chose.
func Identity(env []string) []string {
	out := make([]string, 0, len(env)+3)
	for _, kv := range env {
		switch name, _, _ := strings.Cut(kv, "="); name {
		case "HOME", "USER", "LOGNAME":
		default:
			out = append(out, kv)
		}
	}
	if home := Home(); home != "" {
		out = append(out, "HOME="+home)
	}
	if name := Account(); name != "" {
		out = append(out, "USER="+name, "LOGNAME="+name)
	}
	return out
}

// HelperEnv is the environment for the programs psudo runs for itself: the
// credential-store tools (security, secret-tool), launchctl and the dialogs.
// It is the caller's environment with the parts removed that would send those
// programs somewhere else:
//
//   - HOME, USER and LOGNAME are the account's own. macOS's security tool
//     finds the keychain through HOME: with a HOME the caller chose, it would
//     look in the wrong place, find no keychain, and macOS would offer the
//     user to "Reset To Defaults".
//   - CFFIXED_USER_HOME, LD_* and DYLD_* are dropped.
//   - On Linux the session bus is the standard one of the user, when it
//     exists. A caller that set DBUS_SESSION_BUS_ADDRESS could otherwise have
//     psudo store a secret in, or read approvals from, a service of its own.
func HelperEnv(environ []string) []string {
	out := make([]string, 0, len(environ)+5)
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if name == "CFFIXED_USER_HOME" || strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
			continue
		}
		out = append(out, kv)
	}
	out = Identity(out)
	if runtime.GOOS == "linux" {
		out = pinSessionBus(out, os.Getuid(), ownSocket)
	}
	return out
}

// ownSocket reports whether path is a socket that belongs to the current user.
func ownSocket(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// pinSessionBus points env at the session bus systemd gives each user,
// /run/user/<uid>/bus, when that socket exists. Where it does not (a desktop
// without a systemd user session), the caller's address is all there is and
// it is kept.
func pinSessionBus(env []string, uid int, socket func(path string) bool) []string {
	dir := fmt.Sprintf("/run/user/%d", uid)
	if !socket(dir + "/bus") {
		return env
	}
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		switch name, _, _ := strings.Cut(kv, "="); name {
		case "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR":
		default:
			out = append(out, kv)
		}
	}
	return append(out, "XDG_RUNTIME_DIR="+dir, "DBUS_SESSION_BUS_ADDRESS=unix:path="+dir+"/bus")
}

// NewStore returns the platform credential store for harness.
func NewStore(harness string) (Store, error) {
	switch runtime.GOOS {
	case "darwin":
		return NewKeychain(harness, Run), nil
	case "linux":
		return NewSecretService(harness, Run), nil
	}
	return nil, ErrUnsupported
}

// PurgeExpired deletes the entry when it is no longer fresh, without reading
// the secret on macOS.
func PurgeExpired(s Store, ttl int, now float64) error {
	meta, err := s.Metadata()
	if err != nil {
		return err
	}
	if !Fresh(meta, ttl, now) {
		return s.Clear()
	}
	return nil
}
