package cache

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Reaper manages the macOS launchd task that deletes expired Keychain entries
// without reading their secrets.
type Reaper struct {
	Home string
	UID  int
	Exec ExecFunc
}

const launchctl = "/bin/launchctl"

// Label is the launchd label for harness.
func Label(harness string) string { return "com.harness-root-hook." + harness + ".reaper" }

func (r Reaper) plist(harness string) string {
	return filepath.Join(r.Home, "Library", "LaunchAgents", Label(harness)+".plist")
}

func (r Reaper) bootout(label string) {
	r.Exec(launchctl, []string{"bootout", fmt.Sprintf("gui/%d/%s", r.UID, label)}, nil)
}

// Install writes and loads a task that runs `<binary> --purge-expired=<harness>` every five minutes.
func (r Reaper) Install(harness, binary, configPath string) error {
	r.bootout(Label(harness))
	path := r.plist(harness)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(Plist(harness, binary, configPath)), 0o644); err != nil {
		return err
	}
	res, err := r.Exec(launchctl, []string{"bootstrap", fmt.Sprintf("gui/%d", r.UID), path}, nil)
	if err != nil || res.Code != 0 {
		return fmt.Errorf("launchctl bootstrap failed for %s", Label(harness))
	}
	return nil
}

// Remove unloads and deletes the task for harness only.
func (r Reaper) Remove(harness string) error {
	r.bootout(Label(harness))
	err := os.Remove(r.plist(harness))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// RemoveLegacy unloads and deletes a task by label, ignoring errors.
func (r Reaper) RemoveLegacy(label string) {
	r.bootout(label)
	os.Remove(filepath.Join(r.Home, "Library", "LaunchAgents", label+".plist"))
}

func esc(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// Plist renders the launchd property list.
func Plist(harness, binary, configPath string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + esc(Label(harness)) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + esc(binary) + `</string>
		<string>` + esc("--purge-expired="+harness) + `</string>
	</array>
	<key>StartInterval</key>
	<integer>300</integer>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HARNESS_ROOT_HOOK_CONFIG</key>
		<string>` + esc(configPath) + `</string>
	</dict>
</dict>
</plist>
`
}
