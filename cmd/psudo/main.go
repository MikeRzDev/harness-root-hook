// Command psudo runs a privileged command on this computer or on a host
// reached over SSH. The sudo password is typed into a native dialog and
// never enters the harness's context. See docs/psudo.md.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/MikeRzDev/harness-psudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-psudo-hook/internal/guard"
	"github.com/MikeRzDev/harness-psudo-hook/internal/install"
	"github.com/MikeRzDev/harness-psudo-hook/internal/prompt"
	"github.com/MikeRzDev/harness-psudo-hook/internal/runner"
	"github.com/MikeRzDev/harness-psudo-hook/internal/sysbin"
)

var version = "dev"

const usage = `usage: psudo [-H <host>] [--] <command> [args...]

Runs <command> as root on this computer, or on <host> over SSH. Your sudo
password is entered in a desktop dialog that shows the host and command; it is
never printed or passed in arguments. If <host> needs more than a key to log in
(a password, a one-time code, a key passphrase), ssh's prompts appear in a
dialog too, and the connection is kept for 30 minutes after its last use.

Exit codes: the command's own code, or
  250  no password dialog available     251  dialog cancelled or timed out
  252  sudo rejected the password        255  SSH connection or login failed

Administration:
  psudo --install=claude-code|codex      psudo --uninstall=claude-code|codex
  psudo --clear-cache[=claude-code|codex]
  psudo --ssh-logout                     close the SSH connections psudo keeps
  psudo --version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func executable() string {
	p, err := os.Executable()
	if err != nil {
		return "psudo"
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}

// harnessOf derives the harness from the install location, not from the
// environment, so a caller cannot select another harness's cached password.
func harnessOf(exe string) string {
	if filepath.Base(filepath.Dir(exe)) == "root-hook" {
		return "codex"
	}
	return "claude-code"
}

func validHarness(h string) bool { return h == "claude-code" || h == "codex" }

func titleFor(harness, what string) string {
	if harness == "codex" {
		return what + " (Codex)"
	}
	return what + " (Claude Code)"
}

// askpass is psudo running as ssh's SSH_ASKPASS program during an interactive
// login: the prompt is argv[1], and the answer goes to stdout, which is a
// pipe to ssh. Confirmations (such as accepting an unknown host key) are
// refused rather than shown as a password field.
func askpass(ask prompt.Asker, getenv func(string) string, host string, args []string, stdout, stderr io.Writer) int {
	text := ""
	if len(args) > 0 {
		text = args[0]
	}
	switch kind := getenv("SSH_ASKPASS_PROMPT"); {
	case kind == "none":
		return 0 // a notice, such as "touch your security key"; nothing to answer
	case kind == "confirm" || strings.Contains(strings.ToLower(text), "yes/no"):
		fmt.Fprintf(stderr, "psudo: refused an SSH confirmation for %s (for example an unknown host key); "+
			"connect once with ssh in a terminal to accept it\n", host)
		return 1
	}
	answer, err := ask(context.Background(), prompt.Request{
		Title: titleFor(harnessOf(executable()), "SSH login"), Host: host,
		Text: prompt.LoginMessage(host, text), Timeout: prompt.DefaultTimeout})
	if err != nil {
		return 1
	}
	stdout.Write(append(answer, '\n'))
	for i := range answer {
		answer[i] = 0
	}
	return 0
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if host := os.Getenv(runner.AskpassHostEnv); host != "" {
		// Only a login the runner is performing right now may show a dialog.
		dir, err := runner.ControlDir()
		if err != nil || !runner.AskpassAuthorized(dir, os.Getenv(runner.AskpassTokenEnv)) {
			fmt.Fprintln(stderr, "psudo: refused to show an SSH login dialog that psudo did not start")
			return 1
		}
		return askpass(prompt.System().Ask, os.Getenv, host, args, stdout, stderr)
	}
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if len(args) > 0 && strings.HasPrefix(args[0], "--") && args[0] != "--" {
		return admin(args, stdin, stdout, stderr)
	}
	host := ""
	if len(args) > 0 && args[0] == "-H" {
		if len(args) < 2 {
			fmt.Fprint(stderr, "psudo: -H requires a host\n"+usage)
			return runner.ExitUsage
		}
		host, args = args[1], args[2:]
		if !runner.ValidHost(host) {
			fmt.Fprintln(stderr, "psudo: invalid SSH host")
			return runner.ExitUsage
		}
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	} else if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		fmt.Fprintf(stderr, "psudo: unknown option %q (psudo takes no sudo options)\n%s", args[0], usage)
		return runner.ExitUsage
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return runner.ExitUsage
	}

	exe := executable()
	harness := harnessOf(exe)
	title := titleFor(harness, "sudo password")
	localSudo := sysbin.Find("sudo")
	if host == "" && localSudo == "" {
		fmt.Fprintln(stderr, "psudo: sudo is not installed on this computer")
		return runner.ExitAuthFailed
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	r := &runner.Runner{
		Title:      title,
		Shell:      "/bin/sh",
		LocalSudo:  localSudo,
		SSH:        sysbin.Find("ssh"),
		LocalEnv:   runner.LocalEnv(os.Environ()),
		SSHEnv:     runner.SSHEnv(os.Environ()),
		Ask:        prompt.System().Ask,
		ControlDir: runner.ControlDir,
		Askpass:    exe,
		Store:      func() (cache.Store, error) { return cache.NewStore(harness) },
		TTL:        loadTTL,
		Lock:       func() (func(), error) { return cache.Lock(harness) },
		Now:        time.Now,
		Stdout:     stdout,
		Stderr:     stderr,
		Signals:    sigs,
	}
	return r.Run(context.Background(), host, args)
}

func loadTTL() (int, error) {
	path, err := cache.ConfigPath()
	if err != nil {
		return 0, err
	}
	return cache.LoadConfig(path)
}

func admin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintf(stderr, "psudo: %s takes no further arguments\n", args[0])
		return runner.ExitUsage
	}
	name, value, _ := strings.Cut(strings.TrimPrefix(args[0], "--"), "=")
	exe := executable()
	fail := func(err error) int {
		fmt.Fprintln(stderr, "psudo: "+err.Error())
		return 1
	}
	switch name {
	case "version":
		fmt.Fprintln(stdout, "psudo "+version)
		return 0
	case "ssh-logout":
		if value != "" {
			fmt.Fprintln(stderr, "psudo: --ssh-logout takes no value")
			return runner.ExitUsage
		}
		dir, err := runner.ControlDir()
		if err != nil {
			return fail(err)
		}
		n, err := runner.CloseShared(sysbin.Find("ssh"), dir)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "psudo: closed %d SSH connection(s)\n", n)
		return 0
	case "hook":
		var err error
		switch value {
		case "claude-code":
			err = guard.ClaudeCode(stdin, stdout, exe)
		case "claude-code-session-start":
			err = guard.SessionStart(stdin, stdout, exe, false)
		case "codex-session-start":
			err = guard.Codex(stdin, stdout, exe)
		default:
			fmt.Fprintln(stderr, "psudo: --hook must be claude-code, claude-code-session-start or codex-session-start")
			return runner.ExitUsage
		}
		if err != nil {
			return fail(err)
		}
		return 0
	case "install", "uninstall":
		if !validHarness(value) {
			fmt.Fprintf(stderr, "psudo: --%s must be claude-code or codex\n", name)
			return runner.ExitUsage
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return fail(err)
		}
		in := &install.Installer{
			Home: home, CodexHome: os.Getenv("CODEX_HOME"), GOOS: runtime.GOOS, UID: os.Getuid(),
			Exe: exe, Exec: cache.Run, Store: cache.NewStore, CheckDeps: true, Out: stdout,
		}
		switch name + ":" + value {
		case "install:claude-code":
			err = in.InstallClaudeCode()
		case "uninstall:claude-code":
			err = in.UninstallClaudeCode()
		case "install:codex":
			err = in.InstallCodex()
		case "uninstall:codex":
			err = in.UninstallCodex()
		}
		if err != nil {
			return fail(err)
		}
		return 0
	case "clear-cache", "purge-expired":
		harness := value
		if harness == "" {
			harness = harnessOf(exe)
		}
		if !validHarness(harness) {
			fmt.Fprintf(stderr, "psudo: --%s harness must be claude-code or codex\n", name)
			return runner.ExitUsage
		}
		unlock, err := cache.Lock(harness)
		if err != nil {
			return fail(err)
		}
		defer unlock()
		store, err := cache.NewStore(harness)
		if err != nil {
			return fail(err)
		}
		if name == "clear-cache" {
			err = store.Clear()
		} else {
			var ttl int
			if ttl, err = loadTTL(); err == nil {
				err = cache.PurgeExpired(store, ttl, float64(time.Now().UnixNano())/1e9)
			}
		}
		if err != nil {
			return fail(err)
		}
		return 0
	}
	fmt.Fprintf(stderr, "psudo: unknown option --%s\n%s", name, usage)
	return runner.ExitUsage
}
