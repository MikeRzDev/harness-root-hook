package cache

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const securityPath = "/usr/bin/security"

// Keychain stores records as macOS generic passwords. Secrets reach
// security(1) only through its stdin command interface, never through argv.
type Keychain struct {
	Service, Account string
	Exec             ExecFunc
}

// NewKeychain returns the Keychain entry harness-root-hook.<harness>.
func NewKeychain(harness string, run ExecFunc) *Keychain {
	return &Keychain{Service: "harness-root-hook." + harness, Account: Account(), Exec: run}
}

var icmt = regexp.MustCompile(`"icmt"<blob>="([0-9.]+) ([0-9]+)"`)

func (k *Keychain) run(action string, extra ...string) (Result, error) {
	args := append([]string{action, "-s", k.Service, "-a", k.Account}, extra...)
	return k.Exec(securityPath, args, nil)
}

// Metadata reads the comment attribute only, so expiry checks never decrypt the secret.
func (k *Keychain) Metadata() (*Meta, error) {
	res, err := k.run("find-generic-password")
	if err != nil {
		return nil, err
	}
	m := icmt.FindStringSubmatch(res.Stdout)
	if res.Code != 0 || m == nil {
		return nil, nil
	}
	created, err1 := strconv.ParseFloat(m[1], 64)
	ttl, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return nil, nil
	}
	return &Meta{CreatedAt: created, TTLSeconds: ttl}, nil
}

func (k *Keychain) Load() (*Record, error) {
	res, err := k.run("find-generic-password", "-w")
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(res.Stdout))
	if err != nil {
		return nil, nil
	}
	return ParseRecord(data), nil
}

func quoteSecurity(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func (k *Keychain) Save(r Record) error {
	// Base64 keeps newlines and arbitrary characters out of security's line
	// parser. It is encoding, not encryption; Keychain encrypts.
	encoded := base64.StdEncoding.EncodeToString(r.Encode())
	comment := strconv.FormatFloat(r.CreatedAt, 'f', -1, 64) + " " + strconv.Itoa(r.TTLSeconds)
	args := []string{"add-generic-password", "-U", "-T", securityPath, "-s", k.Service,
		"-a", k.Account, "-j", comment, "-w", encoded}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quoteSecurity(a)
	}
	command := strings.Join(quoted, " ") + "\n"
	if len(command) >= 4096 {
		return errors.New("password record exceeds the Keychain command input limit")
	}
	res, err := k.Exec(securityPath, []string{"-i"}, []byte(command))
	if err != nil || res.Code != 0 {
		return errors.New("could not store the password in Keychain")
	}
	return nil
}

func (k *Keychain) Clear() error {
	res, err := k.run("delete-generic-password")
	if err != nil {
		return err
	}
	if res.Code != 0 && res.Code != 44 { // errSecItemNotFound
		return fmt.Errorf("could not clear the Keychain cache")
	}
	return nil
}
