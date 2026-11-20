package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// A rule names a program, and psudo gives that program the secret without
// asking before each use. That is only worth something while the program is
// the one the user allowed. Often the agent can change it: a script in the
// project, a tool under ~/bin, anything Homebrew installed (those folders
// belong to the user). So for a program that the user's own account can
// change, psudo remembers the SHA-256 of the file when the secret is first
// given to it, and asks again when the file is a different one later: edited,
// replaced, a link pointed elsewhere, or another file of that name earlier in
// the search path.
//
// The first time is trusted as it is; there is nothing to compare with. What
// the pin catches is every change after that. A program that only root can
// change is not pinned: the agent cannot touch it, and an update of the
// system would only cause dialogs.
//
// The pins live in the credential store, next to the approved rules, where the
// agent cannot edit them. The file is read just before the program starts;
// the moment between reading and starting is not covered.

const pinsEntry = "pins"

// replaceable reports whether the file at path, or a folder above it, can be
// changed by the current user: it belongs to the user, or its group or
// everybody may write to it.
func replaceable(path string) bool {
	uid := os.Getuid()
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return true // cannot tell: treat it as something that can change
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) == uid || info.Mode().Perm()&0o022 != 0 {
			return true
		}
		if p == filepath.Dir(p) {
			return false
		}
	}
}

// fileSum is the SHA-256 of the file's contents, in hex.
func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// pinKey names the pin of one secret for one entry of its rule's commands.
// The entry, not the resolved path, is the key: "gh" stays "gh" when another
// file called gh turns up earlier in the search path, and then the sums differ.
func pinKey(secret, entry string) string {
	sum := sha256.Sum256([]byte(secret + "\x00" + entry))
	return hex.EncodeToString(sum[:])
}

// Pins returns the remembered program sums, by pinKey.
func (a *Approvals) Pins() (map[string]string, error) {
	data, err := a.Vault.Get(pinsEntry)
	if err != nil {
		return nil, err
	}
	pins := map[string]string{}
	if data != nil && json.Unmarshal(data, &pins) != nil {
		pins = map[string]string{} // a damaged entry remembers nothing
	}
	return pins, nil
}

// SetPins adds or replaces pins.
func (a *Approvals) SetPins(update map[string]string) error {
	unlock, err := a.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	pins, err := a.Pins()
	if err != nil {
		return err
	}
	for k, v := range update {
		pins[k] = v
	}
	data, _ := json.Marshal(pins)
	return a.Vault.Put(pinsEntry, data)
}
