package install

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
)

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }

type memStore struct{ cleared int }

func (m *memStore) Metadata() (*cache.Meta, error) { return nil, nil }
func (m *memStore) Load() (*cache.Record, error)   { return nil, nil }
func (m *memStore) Save(cache.Record) error        { return nil }
func (m *memStore) Clear() error                   { m.cleared++; return nil }

type fixture struct {
	in    *Installer
	store *memStore
	calls []string
}

func newFixture(t *testing.T, goos string) *fixture {
	home := filepath.Join(t.TempDir(), "home dir")
	os.MkdirAll(home, 0o755)
	t.Setenv("HOME", home)
	t.Setenv("HARNESS_ROOT_HOOK_CONFIG", filepath.Join(home, "config.json"))
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	exe := filepath.Join(t.TempDir(), "psudo-build")
	os.WriteFile(exe, []byte("binary"), 0o755)
	f := &fixture{store: &memStore{}}
	f.in = &Installer{Home: home, GOOS: goos, UID: 501, Exe: exe, Out: io.Discard,
		Store: func(string) (cache.Store, error) { return f.store, nil },
		Exec: func(name string, args []string, _ []byte) (cache.Result, error) {
			f.calls = append(f.calls, name+" "+strings.Join(args, " "))
			return cache.Result{}, nil
		}}
	return f
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const claudeOriginal = `{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/hooks/sudo-check.sh"
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "echo mine"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "true"
          }
        ]
      }
    ]
  },
  "permissions": {}
}
`

func TestClaudeCodeInstallRepeatUninstall(t *testing.T) {
	f := newFixture(t, "linux")
	dir := filepath.Join(f.in.Home, ".claude", "hooks")
	settings := filepath.Join(f.in.Home, ".claude", "settings.json")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(settings, []byte(claudeOriginal), 0o600)
	for _, legacy := range claudeLegacyFiles {
		os.WriteFile(filepath.Join(dir, legacy), []byte("old"), 0o755)
	}
	os.WriteFile(filepath.Join(dir, "unrelated.sh"), []byte("keep"), 0o755)

	if err := f.in.InstallClaudeCode(); err != nil {
		t.Fatal(err)
	}
	first := read(t, settings)
	if strings.Contains(first, "sudo-check.sh") || !strings.Contains(first, jsonString(ClaudeHookCommand)) ||
		!strings.Contains(first, jsonString(ClaudeSessionCommand)) || !strings.Contains(first, `"SessionEnd": [`) ||
		!strings.Contains(first, jsonString(ClaudeSessionEndCommand)+",\n            \"timeout\": 15") {
		t.Fatalf("settings after install:\n%s", first)
	}
	if strings.Index(first, `"model"`) > strings.Index(first, `"hooks"`) || !strings.Contains(first, "echo mine") {
		t.Fatalf("unrelated settings reordered or lost:\n%s", first)
	}
	if read(t, filepath.Join(dir, "psudo")) != "binary" || read(t, settings+".bak") != claudeOriginal {
		t.Fatal("binary or backup missing")
	}
	if info, _ := os.Stat(settings); info.Mode().Perm() != 0o600 {
		t.Fatalf("settings mode changed to %v", info.Mode())
	}
	for _, legacy := range claudeLegacyFiles {
		if _, err := os.Stat(filepath.Join(dir, legacy)); err == nil {
			t.Fatalf("legacy %s not removed", legacy)
		}
	}
	if err := f.in.InstallClaudeCode(); err != nil {
		t.Fatal(err)
	}
	if read(t, settings) != first {
		t.Fatal("second install changed settings")
	}

	if err := f.in.UninstallClaudeCode(); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(claudeOriginal, `      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/hooks/sudo-check.sh"
          }
        ]
      },
`, "", 1)
	if got := read(t, settings); got != want {
		t.Fatalf("after uninstall:\n%s\nwant:\n%s", got, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "psudo")); err == nil || f.store.cleared != 1 {
		t.Fatal("binary not removed or cache not cleared")
	}
	if read(t, filepath.Join(dir, "unrelated.sh")) != "keep" {
		t.Fatal("unrelated file removed")
	}
}

func TestClaudeCodeFreshHomeAndDarwinTasks(t *testing.T) {
	f := newFixture(t, "darwin")
	if err := f.in.InstallClaudeCode(); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(f.in.Home, "Library/LaunchAgents/com.harness-root-hook.claude-code.reaper.plist")
	if !strings.Contains(read(t, plist), filepath.Join(f.in.Home, ".claude/hooks/psudo")) {
		t.Fatal("reaper does not run the installed binary")
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{"bootout gui/501/com.claude.sudo-reaper", "delete-generic-password -s claude-sudo",
		"bootstrap gui/501 " + plist} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing call %q in\n%s", want, joined)
		}
	}
	if err := f.in.UninstallClaudeCode(); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(f.in.Home, ".claude/settings.json")); got != "{}\n" {
		t.Fatalf("settings after uninstall %q", got)
	}
	if _, err := os.Stat(plist); err == nil {
		t.Fatal("reaper plist left behind")
	}
}

func TestCodexInstallRepeatUninstall(t *testing.T) {
	f := newFixture(t, "linux")
	f.in.CodexHome = filepath.Join(f.in.Home, "codex home 'quoted'")
	dest, _ := f.in.CodexDir()
	os.MkdirAll(dest, 0o700)
	settings := filepath.Join(f.in.CodexHome, "hooks.json")
	original := `{
  "description": "mine",
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "echo mine"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "true"
          }
        ]
      }
    ]
  }
}
`
	legacyGroup := `,
      {
        "hooks": [
          {
            "type": "command",
            "command": ` + jsonString("python3 "+shquote.Quote(filepath.Join(dest, "context.py"))) + `,
            "timeout": 10
          }
        ]
      }`
	withLegacy := strings.Replace(original, "        ]\n      }\n    ],\n    \"Stop\"", "        ]\n      }"+legacyGroup+"\n    ],\n    \"Stop\"", 1)
	os.WriteFile(settings, []byte(withLegacy), 0o644)
	if !strings.Contains(withLegacy, "context.py") {
		t.Fatal("fixture setup")
	}
	for _, legacy := range codexLegacyFiles {
		os.WriteFile(filepath.Join(dest, legacy), []byte("old"), 0o700)
	}
	if err := f.in.InstallCodex(); err != nil {
		t.Fatal(err)
	}
	first := read(t, settings)
	if strings.Contains(first, "context.py") || !strings.Contains(first, jsonString(shquote.Quote(filepath.Join(dest, "psudo"))+" --hook=codex-session-start")) {
		t.Fatalf("hooks.json after install:\n%s", first)
	}
	if read(t, filepath.Join(f.in.CodexHome, "hooks.json.before-root-hook")) != withLegacy {
		t.Fatal("backup missing")
	}
	f.in.InstallCodex()
	if read(t, settings) != first {
		t.Fatal("second install changed hooks.json")
	}
	os.WriteFile(filepath.Join(dest, "unrelated"), []byte("keep"), 0o600)
	if err := f.in.UninstallCodex(); err != nil {
		t.Fatal(err)
	}
	if got := read(t, settings); got != original {
		t.Fatalf("after uninstall:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(dest, "psudo")); err == nil || read(t, filepath.Join(dest, "unrelated")) != "keep" {
		t.Fatal("uninstall removed the wrong files")
	}
}

func TestInvalidSettingsAreNotModified(t *testing.T) {
	for _, bad := range []string{"{", "[]", `{"hooks": []}`, `{"hooks": {"SessionStart": {}}}`,
		`{"hooks": {"SessionStart": [1]}}`, `{"hooks": {"SessionStart": [{"hooks": {}}]}}`} {
		f := newFixture(t, "linux")
		f.in.CodexHome = filepath.Join(f.in.Home, ".codex")
		os.MkdirAll(f.in.CodexHome, 0o755)
		settings := filepath.Join(f.in.CodexHome, "hooks.json")
		os.WriteFile(settings, []byte(bad), 0o644)
		if err := f.in.InstallCodex(); err == nil {
			t.Errorf("%s: accepted", bad)
		}
		if read(t, settings) != bad {
			t.Errorf("%s: modified", bad)
		}
		if _, err := os.Stat(filepath.Join(f.in.CodexHome, "root-hook")); err == nil {
			t.Errorf("%s: files installed", bad)
		}
	}
}

func TestRefusesSymlinkTarget(t *testing.T) {
	f := newFixture(t, "linux")
	dir := filepath.Join(f.in.Home, ".claude", "hooks")
	os.MkdirAll(dir, 0o755)
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("victim"), 0o644)
	os.Symlink(victim, filepath.Join(dir, "psudo"))
	var out bytes.Buffer
	f.in.Out = &out
	if err := f.in.InstallClaudeCode(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err %v", err)
	}
	if read(t, victim) != "victim" {
		t.Fatal("symlink target overwritten")
	}
}
