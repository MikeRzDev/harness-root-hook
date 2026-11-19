// Package guard implements the harness hooks: the Claude Code PreToolUse
// policy that denies bare sudo/sshpass (spec §6.4), and the Codex
// SessionStart context that introduces psudo.
package guard

import (
	"encoding/json"
	"io"
	"regexp"

	"github.com/MikeRzDev/harness-root-hook/internal/shquote"
)

// pattern matches sudo or sshpass as standalone words, like grep -w.
// "psudo" does not match because "p" is a word character.
var pattern = regexp.MustCompile(`(^|[^A-Za-z0-9_])(sudo|sshpass)([^A-Za-z0-9_]|$)`)

// Denied reports whether a Bash command must be refused.
func Denied(command string) bool { return pattern.MatchString(command) }

// Reason is shown to the model when a command is denied.
func Reason(psudo string) string {
	return "Use `psudo <command>` (local) or `psudo -H <host> <command>` (remote). " +
		"psudo is installed at " + shquote.Quote(psudo) + "; invoke it by that path if `psudo` is not on PATH. " +
		"Never ask for or handle the password."
}

type hookOutput struct {
	HookSpecificOutput map[string]string `json:"hookSpecificOutput"`
}

func encode(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func deny(out io.Writer, psudo string) error {
	return encode(out, hookOutput{map[string]string{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": Reason(psudo),
	}})
}

// ClaudeCode reads a PreToolUse event and writes a deny decision when the
// command invokes sudo or sshpass. Unparseable input is denied (fail closed).
func ClaudeCode(in io.Reader, out io.Writer, psudo string) error {
	var event struct {
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if err := json.NewDecoder(in).Decode(&event); err != nil {
		return deny(out, psudo)
	}
	if event.ToolName != "" && event.ToolName != "Bash" {
		return nil
	}
	var input struct {
		Command *string `json:"command"`
	}
	if len(event.ToolInput) > 0 && json.Unmarshal(event.ToolInput, &input) != nil {
		return deny(out, psudo)
	}
	if input.Command != nil && Denied(*input.Command) {
		return deny(out, psudo)
	}
	return nil
}

// SessionContext is the SessionStart guidance that introduces psudo. The
// model learns about remote hosts here: the PreToolUse guard only sees
// commands that contain sudo, not "ssh root@host".
func SessionContext(psudo string, codex bool) string {
	p := shquote.Quote(psudo)
	s := "For authorized commands that need root, on this computer or on SSH hosts, use psudo: run " +
		p + " <command> [args...] on this computer, or " + p + " -H <ssh-host> <command> [args...] on a host reached over SSH. " +
		"For root on a remote host use psudo -H, not ssh root@<host>, ssh <host> sudo ..., sudo -S, or sshpass. " +
		"The arguments are passed through exactly; use " + p + " sh -c '...' for pipelines; psudo takes no sudo options. " +
		"psudo shows the user a native dialog naming the host and command for the sudo password, and, if the host " +
		"needs a code or password to log in over SSH, a dialog for that too. Never ask the user for a password or " +
		"code in chat, and never pipe one into a command. Keep the actual command visible in the tool call. " +
		"Exit 251: the user cancelled; stop that privileged action. 252: authentication failed (the psudo: line says " +
		"WRONG PASSWORD, NOT PERMITTED or AUTHENTICATION FAILED); report it and do not retry another way. " +
		"255: the SSH connection or login failed. The command's stdin is closed; a command that needs a terminal " +
		"must be run by the user."
	if codex {
		s += " Follow normal sandbox escalation and approval requirements; psudo does not grant approval."
	}
	return s
}

// CodexContext is the SessionStart guidance for Codex.
func CodexContext(psudo string) string { return SessionContext(psudo, true) }

// Codex handles a Codex hook event, emitting context only for SessionStart.
func Codex(in io.Reader, out io.Writer, psudo string) error {
	return SessionStart(in, out, psudo, true)
}

// SessionStart writes the context for a SessionStart event and nothing for
// any other event.
func SessionStart(in io.Reader, out io.Writer, psudo string, codex bool) error {
	var event struct {
		Name string `json:"hook_event_name"`
	}
	if err := json.NewDecoder(in).Decode(&event); err != nil {
		return err
	}
	if event.Name != "SessionStart" {
		return nil
	}
	return encode(out, map[string]map[string]string{"hookSpecificOutput": {
		"hookEventName": "SessionStart", "additionalContext": SessionContext(psudo, codex),
	}})
}
