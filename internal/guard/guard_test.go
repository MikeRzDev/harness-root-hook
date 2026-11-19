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
		"grep error /var/log/sudo.log":          "allow",
		"ls /etc/sudoers.d":                     "allow",
		"grep pseudo notes.txt":                 "allow",

		// The word as data: these blocked real work before.
		"cat >> specs/PROGRESS.md <<'EOF'\n13. Ran `sudo fleet-ca krl push` through psudo.\nEOF": "allow",
		"cat > notes.md <<EOF\nsudo is denied; use psudo\nEOF":                                   "allow",
		`git commit -m "Explain why sudo is denied"`:                                             "allow",
		`grep -rn 'sudo' docs`:                                      "allow",
		`echo "run psudo, not sudo"`:                                "allow",
		"# sudo is not used here\nls":                               "allow",
		"/home/u/.claude/hooks/psudo sh -c 'sudo -u postgres psql'": "allow",
		"env cat > f <<'EOF'\nsudo\nEOF":                            "allow",
		"cat <<'EOF'\n$(sudo id)\nEOF":                              "allow",

		// Ways to actually run it: all denied.
		"env FOO=1 sudo id":          "deny",
		"FOO=1 sudo id":              "deny",
		"xargs sudo rm < list":       "deny",
		"nohup sudo id &":            "deny",
		"time sudo id":               "deny",
		"! sudo id":                  "deny",
		"exec sudo id":               "deny",
		"2>/dev/null sudo id":        "deny",
		`"sudo" id`:                  "deny",
		`s\udo id`:                   "deny",
		"'/usr/bin/sudo' id":         "deny",
		"echo $(sudo id)":            "deny",
		"echo \"$(sudo id)\"":        "deny",
		"x=`sudo id`":                "deny",
		"cat <<EOF\n$(sudo id)\nEOF": "deny",
		"ssh host 'sudo systemctl restart nginx'": "deny",
		"bash -c \"sudo id\"":                     "deny",
		`echo "sudo id" | sh`:                     "deny",
		"ssh host <<'EOF'\nsudo id\nEOF":          "deny",
		"sh <<< 'sudo id'":                        "deny",
		"S=sudo; $S id":                           "deny",
		"if true; then sudo id; fi":               "deny",
		"{ sudo id; }":                            "deny",
		"for h in a b; do sudo id; done":          "deny",
		"ls &&\nsudo id":                          "deny",
		"ls | sudo tee /etc/x":                    "deny",
		"echo 'unterminated sudo":                 "deny", // unparseable: falls back to the word match
		"eval \"sudo id\"":                        "deny",
		"watch sudo id":                           "deny",

		// Found by review: interpreters, more wrappers, unknown programs, fake psudo.
		"python3 - <<'EOF'\nprint('sudo')\nEOF":          "deny",
		"python3 -c 'import os; os.system(\"sudo id\")'": "deny",
		"perl -e 'system \"sudo id\"'":                   "deny",
		"awk 'BEGIN{system(\"sudo id\")}'":               "deny",
		"find . -name x -exec sudo rm {} +":              "deny",
		"setsid sudo id":                                 "deny",
		"flock /tmp/l sudo id":                           "deny",
		"make SUDO=sudo install":                         "deny",
		"/tmp/psudo sudo id":                             "deny",
		"psudo sh -c 'sudo id'":                          "deny",
		"git -c alias.x='!sudo id' x":                    "deny",
		"gh alias set x '!sudo id'":                      "deny",
		"echo 'sudo id' | python3":                       "deny",

		// Found by review: variables and exec options on data programs.
		"GIT_PAGER='sudo id' git log":                "deny",
		"env GIT_PAGER='sudo id' git log":            "deny",
		"LESSOPEN='|sudo id %s' less f":              "deny",
		"man -P 'sudo id' ls":                        "deny",
		"rg --pre 'sudo id' pattern":                 "deny",
		"sort --compress-program=sudo f":             "deny",
		"git --upload-pack='sudo x' fetch origin":    "deny",
		"git commit -m 'fix' --exec-path='sudo x'":   "deny",
		"git config alias.x '!sudo id'":              "deny",
		"ln -s /usr/bin/sudo ./x":                    "deny",
		"git commit -F - <<'EOF'\nExplain sudo\nEOF": "allow",
		"git commit --message='Explain sudo'":        "allow",
		"tee notes.md <<< 'use psudo, not sudo'":     "allow",

		// Found by review: computed names, ANSI-C quoting, ${…}, $((…)), case.
		`$'\x73udo' id`:                       "deny",
		`sh -c $'\x73udo id'`:                 "deny",
		"${SUDO:-sudo} id":                    "deny",
		"$EDITOR notes.md":                    "deny",
		"echo ${x:-$(sudo id)}":               "deny",
		"echo $(( $(sudo id) + 1 ))":          "deny",
		"echo $(case x in a) sudo id;; esac)": "deny",
		`echo $'tab\there'`:                   "allow",
		"echo $((1 + 2))":                     "allow",
		"echo ${HOME}/notes":                  "allow",
	} {
		if got := decide(t, bash(command)); got != want {
			t.Errorf("%q: %s, want %s", command, got, want)
		}
	}
}

func TestPasswordCacheReadsAreDenied(t *testing.T) {
	for command, want := range map[string]string{
		"security find-generic-password -w -s harness-root-hook.claude-code": "deny",
		"/usr/bin/security find-generic-password -s harness-root-hook.codex": "deny",
		"secret-tool lookup application harness-root-hook harness codex":     "deny",
		"bash -c 'security find-generic-password -w -s harness-root-hook.x'": "deny",
		"security find-generic-password -s some-other-service":               "allow",
		"psudo --clear-cache":              "allow",
		"grep harness-root-hook README.md": "allow",
	} {
		if got := decide(t, bash(command)); got != want {
			t.Errorf("%q: %s, want %s", command, got, want)
		}
	}
	var out bytes.Buffer
	ClaudeCode(strings.NewReader(bash("security find-generic-password -w -s harness-root-hook.codex")), &out, "/p")
	if !strings.Contains(out.String(), "must never be read") {
		t.Fatalf("cache reason %s", out.String())
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
