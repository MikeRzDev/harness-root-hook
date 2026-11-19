package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/MikeRzDev/harness-psudo-hook/internal/prompt"
	"github.com/MikeRzDev/harness-psudo-hook/internal/runner"
)

// Only error paths are exercised here; a valid command would open a real dialog.
func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"-u", "root", "id"}, {"-H"}, {"-H", "-oProxyCommand=x", "id"},
		{"-H", "a b", "id"}, {"-H", "host"}, {"--"}, {"--bogus"}, {"--install=other"}, {"--hook=x"},
		{"--version", "extra"}} {
		var out, errb bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	var out bytes.Buffer
	if run([]string{"--version"}, nil, &out, &out) != 0 || !strings.HasPrefix(out.String(), "psudo ") {
		t.Fatal(out.String())
	}
	out.Reset()
	if run([]string{"--help"}, nil, &out, &out) != 0 || !strings.Contains(out.String(), "-H <host>") {
		t.Fatal(out.String())
	}
}

func TestHookDispatch(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"sudo id"}}`)
	if run([]string{"--hook=claude-code"}, in, &out, &out) != 0 || !strings.Contains(out.String(), `"deny"`) {
		t.Fatal(out.String())
	}
}

func TestHarnessFromInstallLocation(t *testing.T) {
	for path, want := range map[string]string{"/h/.codex/root-hook/psudo": "codex",
		"/h/.claude/hooks/psudo": "claude-code", "/usr/local/bin/psudo": "claude-code"} {
		if got := harnessOf(path); got != want {
			t.Errorf("%s: %s", path, got)
		}
	}
}

func TestAskpassAnswersLoginPromptsAndRefusesConfirmations(t *testing.T) {
	var asked []prompt.Request
	ask := func(_ context.Context, req prompt.Request) ([]byte, error) {
		asked = append(asked, req)
		return []byte("123456"), nil
	}
	env := func(kind string) func(string) string {
		return func(k string) string {
			if k == "SSH_ASKPASS_PROMPT" {
				return kind
			}
			return ""
		}
	}
	var out, errb bytes.Buffer
	if code := askpass(ask, env(""), "pi", []string{"(dietpi@pi) Verification code: "}, &out, &errb); code != 0 || out.String() != "123456\n" {
		t.Fatalf("exit %d out %q", code, out.String())
	}
	if len(asked) != 1 || asked[0].Host != "pi" || !strings.Contains(asked[0].Text, "Verification code:") ||
		!strings.Contains(asked[0].Title, "SSH login") {
		t.Fatalf("dialog %+v", asked)
	}
	for _, c := range []struct{ kind, text string }{
		{"", "Are you sure you want to continue connecting (yes/no/[fingerprint])?"},
		{"confirm", "Allow use of key?"},
	} {
		out.Reset()
		if code := askpass(ask, env(c.kind), "pi", []string{c.text}, &out, &errb); code != 1 || out.Len() != 0 {
			t.Fatalf("%q: exit %d out %q", c.text, code, out.String())
		}
	}
	if code := askpass(ask, env("none"), "pi", []string{"Confirm user presence"}, &out, &errb); code != 0 || len(asked) != 1 {
		t.Fatalf("notice: exit %d dialogs %d", code, len(asked))
	}
	cancel := func(context.Context, prompt.Request) ([]byte, error) { return nil, prompt.ErrCancelled }
	out.Reset()
	if code := askpass(cancel, env(""), "pi", []string{"Password:"}, &out, &errb); code != 1 || out.Len() != 0 {
		t.Fatalf("cancel: exit %d out %q", code, out.String())
	}
}

func TestAskpassModeRefusesWithoutALiveLogin(t *testing.T) {
	t.Setenv(runner.AskpassHostEnv, "evil")
	for _, tok := range []string{"", strings.Repeat("a", 64), "../../etc/passwd"} {
		t.Setenv(runner.AskpassTokenEnv, tok)
		var out, errb bytes.Buffer
		if code := run([]string{"Password:"}, nil, &out, &errb); code != 1 || out.Len() != 0 ||
			!strings.Contains(errb.String(), "did not start") {
			t.Fatalf("token %q: exit %d out %q err %q", tok, code, out.String(), errb.String())
		}
	}
}
