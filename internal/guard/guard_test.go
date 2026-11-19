package guard

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func decide(t *testing.T, input string) string {
	t.Helper()
	var out bytes.Buffer
	if err := ClaudeCode(strings.NewReader(input), &out, "/home/u/.claude/hooks/psudo"); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		return "allow"
	}
	var res struct{ HookSpecificOutput map[string]string }
	json.Unmarshal(out.Bytes(), &res)
	return res.HookSpecificOutput["permissionDecision"]
}

func bash(command string) string {
	b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": command}})
	return string(b)
}

// The decision matrix from spec §6.4, plus a few boundary cases.
func TestDecisionMatrix(t *testing.T) {
	for command, want := range map[string]string{
		"sudo apt install x":                    "deny",
		"ssh host sudo systemctl restart nginx": "deny",
		"echo secret | sudo -S id":              "deny",
		"sshpass -p pw ssh host":                "deny",
		"psudo apt install x":                   "allow",
		"psudo -H host systemctl restart nginx": "allow",
		"psudo ls && sudo rm x":                 "deny",
		"cat /etc/sudoers":                      "allow",
		"/usr/bin/sudo id":                      "deny",
		"echo ok\nsudo id":                      "deny",
		"(sudo id)":                             "deny",
		"~/.claude/hooks/psudo id -u":           "allow",
		"cat ~/.claude/hooks/psudo":             "allow",
		"grep error /var/log/sudo.log":          "deny", // documented false positive
		"ls /etc/sudoers.d":                     "allow",
		"grep pseudo notes.txt":                 "allow",
	} {
		if got := decide(t, bash(command)); got != want {
			t.Errorf("%q: %s, want %s", command, got, want)
		}
	}
}

func TestReasonAndFailClosed(t *testing.T) {
	var out bytes.Buffer
	ClaudeCode(strings.NewReader(bash("sudo id")), &out, "/p/psudo")
	if !strings.Contains(out.String(), "`psudo -H <host> <command>`") || !strings.Contains(out.String(), "/p/psudo") {
		t.Fatalf("reason %s", out.String())
	}
	if decide(t, "not json") != "deny" {
		t.Fatal("unparseable input allowed")
	}
	if decide(t, `{"tool_name":"Read","tool_input":{"file_path":"/etc/sudoers"}}`) != "allow" {
		t.Fatal("non-Bash tool denied")
	}
}

func TestCodexContext(t *testing.T) {
	var out bytes.Buffer
	if err := Codex(strings.NewReader(`{"hook_event_name":"SessionStart"}`), &out, "/c/root-hook/psudo"); err != nil {
		t.Fatal(err)
	}
	var res struct{ HookSpecificOutput map[string]string }
	json.Unmarshal(out.Bytes(), &res)
	ctx := res.HookSpecificOutput["additionalContext"]
	if !strings.Contains(ctx, "/c/root-hook/psudo -H <ssh-host>") || res.HookSpecificOutput["permissionDecision"] != "" {
		t.Fatalf("context %q", out.String())
	}
	out.Reset()
	Codex(strings.NewReader(`{"hook_event_name":"PermissionRequest"}`), &out, "/p")
	if out.Len() != 0 {
		t.Fatal("context emitted for another event")
	}
}
