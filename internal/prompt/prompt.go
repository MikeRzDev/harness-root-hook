// Package prompt shows a native password dialog on the harness machine. The
// host and command are always passed to the dialog program as separate
// arguments (data), never spliced into script source.
package prompt

import (
	"bytes"
	"context"
	"errors"
	"html"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/MikeRzDev/harness-root-hook/internal/sysbin"
)

var (
	// ErrNoProvider means no dialog can be shown here (for example, no display).
	ErrNoProvider = errors.New("no password dialog is available")
	// ErrCancelled means the user cancelled, the dialog timed out, or the input was unusable.
	ErrCancelled = errors.New("password dialog cancelled or timed out")
)

// DefaultTimeout is shorter than Claude Code's default 120 s Bash timeout.
const DefaultTimeout = 90 * time.Second

// Request describes what the user is asked to authorize.
type Request struct {
	Title   string
	Host    string // empty means the local machine
	Command string // already rendered for display
	Text    string // when set, the whole dialog body instead of the sudo message
	Timeout time.Duration
}

func (req Request) message() string {
	if req.Text != "" {
		return req.Text
	}
	return Message(req.Host, req.Command)
}

// LoginMessage is the dialog body for one of ssh's own login prompts (a
// password, a one-time code, a key passphrase), shown while psudo logs in.
func LoginMessage(host, sshPrompt string) string {
	return "Host: " + host + "\n\nSSH login asks:\n" + strings.TrimSpace(sshPrompt) +
		"\n\nThis answer goes only to ssh, to log in to " + host +
		". psudo asks for the sudo password separately."
}

// Asker returns the password or ErrNoProvider / ErrCancelled. Alternative
// providers (for example a phone approval) implement the same signature.
type Asker func(ctx context.Context, req Request) ([]byte, error)

// Message is the dialog body.
func Message(host, command string) string {
	label := host
	if label == "" {
		label = "this computer"
	}
	return "Host: " + label + "\n\nCommand:\n" + command + "\n\nEnter your sudo password on " + label + " to run this command."
}

// macScript is fixed. Title, message and timeout arrive as argv items.
const macScript = `on run argv
set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer "" with hidden answer with icon caution giving up after ((item 3 of argv) as integer)
if gave up of r then error number -128
return text returned of r
end run`

// Env abstracts the environment so dialog selection is testable.
type Env struct {
	GOOS   string
	Getenv func(string) string
	Find   func(string) string
	// Run executes the dialog and returns stdout and the exit code. A non-nil
	// error means the program could not be started.
	Run func(ctx context.Context, name string, args []string) ([]byte, int, error)
}

// System is the production environment.
func System() Env {
	return Env{GOOS: runtime.GOOS, Getenv: os.Getenv, Find: sysbin.Find, Run: runDialog}
}

func runDialog(ctx context.Context, name string, args []string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out.Bytes(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return nil, -1, err
	}
	return out.Bytes(), 0, nil
}

// pangoEscape escapes text for GTK markup labels (zenity --text).
func pangoEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// Command picks the dialog program and its argument vector.
func (e Env) Command(req Request) (string, []string, error) {
	msg := req.message()
	seconds := int(req.Timeout / time.Second)
	if seconds <= 0 {
		seconds = int(DefaultTimeout / time.Second)
	}
	switch e.GOOS {
	case "darwin":
		return "/usr/bin/osascript", []string{"-e", macScript, req.Title, msg, strconv.Itoa(seconds)}, nil
	case "linux":
		display, wayland := e.Getenv("DISPLAY"), e.Getenv("WAYLAND_DISPLAY")
		if display == "" && wayland == "" {
			return "", nil, ErrNoProvider
		}
		if p := e.Find("zenity"); p != "" {
			return p, []string{"--entry", "--hide-text", "--title=" + req.Title,
				"--text=" + pangoEscape(msg), "--timeout=" + strconv.Itoa(seconds)}, nil
		}
		if p := e.Find("kdialog"); p != "" {
			// <qt><pre> forces rich text, so escaped content renders verbatim.
			return p, []string{"--title", req.Title, "--password",
				"<qt><pre>" + html.EscapeString(msg) + "</pre></qt>"}, nil
		}
		if p := e.Find("ssh-askpass"); p != "" && display != "" {
			return p, []string{msg}, nil
		}
	}
	return "", nil, ErrNoProvider
}

// Ask shows the dialog and returns the password.
func (e Env) Ask(ctx context.Context, req Request) ([]byte, error) {
	if req.Timeout <= 0 {
		req.Timeout = DefaultTimeout
	}
	name, args, err := e.Command(req)
	if err != nil {
		return nil, err
	}
	// Hard stop slightly after the dialog's own timeout; expiry is a cancel.
	ctx, cancel := context.WithTimeout(ctx, req.Timeout+5*time.Second)
	defer cancel()
	out, code, err := e.Run(ctx, name, args)
	if err != nil {
		return nil, ErrNoProvider
	}
	if code != 0 || ctx.Err() != nil {
		return nil, ErrCancelled
	}
	password := bytes.TrimSuffix(out, []byte("\n"))
	if len(password) == 0 || bytes.ContainsAny(password, "\n\r\x00") {
		return nil, ErrCancelled
	}
	return password, nil
}
