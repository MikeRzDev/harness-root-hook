package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"
)

// A rule names a program, and psudo gives that program the secret without
// asking before each use. That is only worth something while the program is
// the one the user allowed. Often the agent can change it: a script in the
// project, a tool under ~/bin, anything Homebrew installed (those folders
// belong to the user). So psudo remembers the SHA-256 of the program file when
// a stored secret is first given to it, and asks again when the file is a
// different one later: edited, replaced, a link pointed elsewhere, or another
// file of that name earlier in the search path.
//
// Every local program is pinned, also one that only root can change. Leaving
// those out looked harmless and was not: a rule's entry can be a link in a
// folder of the user, and a link pointed at a root-owned program (an
// interpreter, say) would then have gone unchecked. The price is one dialog
// when a system update changes a pinned program.
//
// The first time is trusted as it is; there is nothing to compare with. What
// the pin catches is every change after that.
//
// The pins live in the credential store, next to the approved rules, where the
// agent cannot edit them.
//
// The file is read just before the program starts, and what is started has to
// be what was read. psudo cannot start a program from the bytes it has hashed
// in a way that works on every system and for every kind of program, so it
// compares the file's identity (device, inode, size, modification time and
// change time) before and after reading it and once more right before the
// start, and refuses when anything differs. A swap or an edit would have to
// fall into the instant between that last look and the start, and every
// attempt that misses shows up as a refusal or as a "Program changed" dialog.

const pinsEntry = "pins"

// fileIdentity describes which file is at path right now and whether it has
// been touched: device, inode, size, modification time and change time.
func fileIdentity(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("no file identity for %s", path)
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d", uint64(st.Dev), uint64(st.Ino), info.Size(), info.ModTime().UnixNano(), changeTime(st)), nil
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
