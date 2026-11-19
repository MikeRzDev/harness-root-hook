package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/MikeRzDev/harness-root-hook/internal/cache"
)

// AskpassHostEnv is set, with the host as its value, only on the ssh process
// psudo uses to log in interactively. ssh then runs psudo as its SSH_ASKPASS
// program, and psudo shows each login prompt in a dialog.
const AskpassHostEnv = "PSUDO_SSH_ASKPASS_HOST"

// AskpassTokenEnv carries a one-time token. Askpass mode answers only while
// the matching file exists in psudo's private directory, which the runner
// creates just before an interactive login and removes right after it. Setting
// the environment variables alone is therefore not enough to get a
// psudo-titled dialog whose answer goes to stdout.
const AskpassTokenEnv = "PSUDO_SSH_ASKPASS_TOKEN"

func tokenFile(dir, token string) string { return filepath.Join(dir, "askpass-"+token) }

// AskpassAuthorized reports whether token belongs to a login psudo is running.
func AskpassAuthorized(dir, token string) bool {
	if len(token) != 64 || strings.Trim(token, "0123456789abcdef") != "" {
		return false
	}
	info, err := os.Lstat(tokenFile(dir, token))
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DefaultPersist is how long psudo keeps an SSH connection it logged in
// interactively after its last use.
const DefaultPersist = 30 * time.Minute

// loginTimeout bounds an interactive login, which can ask several questions
// (for example a password and then a one-time code), each in its own dialog.
const loginTimeout = 5 * time.Minute

// ControlDir is the private directory for psudo's shared SSH connections. It
// is short on purpose: a socket path must fit in 104 bytes on macOS.
func ControlDir() (string, error) {
	dir := fmt.Sprintf("/tmp/psudo-%d", os.Getuid())
	if runtime.GOOS == "linux" {
		if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" && filepath.IsAbs(x) && len(x) <= 32 {
			dir = filepath.Join(x, "psudo")
		}
	}
	if err := cache.PrivateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func controlPath(dir string) string { return filepath.Join(dir, "%C") }

// sharedOpts reuse psudo's own connection to the host when one is open, and
// otherwise connect normally. They never create a connection.
func sharedOpts(dir string) []string {
	return []string{"-o", "ControlMaster=no", "-o", "ControlPath=" + controlPath(dir)}
}

func (r *Runner) ssh(ctx context.Context, env []string, stderr io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, r.SSH, args...)
	cmd.Env = env
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	// A connection kept in the background must not hold the call open.
	cmd.WaitDelay = 3 * time.Second
	return cmd.Run()
}

// connect makes sure host can be reached before any dialog for sudo, and
// returns the extra ssh options the command must use. In order:
//  1. a connection psudo logged in earlier and still keeps;
//  2. the user's own ssh configuration with key authentication only;
//  3. an interactive login, when key authentication is not enough: ssh's own
//     prompts (password, one-time code, key passphrase) go to a dialog, and
//     psudo keeps the connection for Persist after its last use.
func (r *Runner) connect(ctx context.Context, host string) ([]string, bool) {
	dir := ""
	if r.ControlDir != nil {
		if d, err := r.ControlDir(); err == nil {
			dir = d
		}
	}
	if dir != "" {
		check := append(sharedOpts(dir), "-O", "check", "--", host)
		if r.ssh(ctx, r.SSHEnv, io.Discard, check...) == nil {
			return sharedOpts(dir), true
		}
	}

	var keyErr bytes.Buffer
	if r.ssh(ctx, r.SSHEnv, &keyErr, SSHArgs(host, "true")...) == nil {
		return nil, true
	}
	if dir == "" || r.Askpass == "" {
		r.Stderr.Write(keyErr.Bytes())
		r.fail("cannot reach %s over SSH with key authentication; no password was requested", host)
		return nil, false
	}

	persist := r.Persist
	if persist <= 0 {
		persist = DefaultPersist
	}
	token, err := newToken()
	if err != nil {
		r.fail("SSH FAILED: could not prepare the SSH login for %s. No sudo password was requested.", host)
		return nil, false
	}
	tf, err := os.OpenFile(tokenFile(dir, token), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		r.fail("SSH FAILED: could not prepare the SSH login for %s. No sudo password was requested.", host)
		return nil, false
	}
	tf.Close()
	defer os.Remove(tokenFile(dir, token))
	env := append(append([]string(nil), r.SSHEnv...),
		"SSH_ASKPASS="+r.Askpass, "SSH_ASKPASS_REQUIRE=force", AskpassHostEnv+"="+host, AskpassTokenEnv+"="+token)
	login := []string{"-T", "-o", "ControlMaster=yes", "-o", "ControlPath=" + controlPath(dir),
		"-o", "ControlPersist=" + strconv.Itoa(int(persist/time.Second)),
		"-o", "ConnectTimeout=15", "-o", "NumberOfPasswordPrompts=1", "--", host, "true"}
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	var loginErr bytes.Buffer
	if err := r.ssh(ctx, env, &loginErr, login...); err != nil {
		r.Stderr.Write(loginErr.Bytes())
		r.fail("SSH FAILED: could not connect to or log in to %s (ssh's reason is above; an SSH login "+
			"dialog that was cancelled, timed out or answered wrongly ends here too). No sudo password was requested.", host)
		return nil, false
	}
	r.fail("logged in to %s over SSH; psudo keeps this connection for %d minutes after its last use "+
		"(psudo --ssh-logout closes it now)", host, int(persist/time.Minute))
	return sharedOpts(dir), true
}

// CloseShared ends every SSH connection psudo keeps in dir and returns how
// many it closed.
func CloseShared(sshPath, dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.Type()&os.ModeSocket == 0 {
			continue
		}
		path := filepath.Join(dir, e.Name())
		cmd := exec.Command(sshPath, "-o", "ControlPath="+path, "-O", "exit", "psudo-shared")
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if cmd.Run() == nil {
			n++
		} else {
			os.Remove(path) // a stale socket whose connection is already gone
		}
	}
	return n, nil
}
