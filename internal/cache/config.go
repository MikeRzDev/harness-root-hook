// Package cache implements the fixed-duration sudo password cache shared by
// the Claude Code and Codex integrations. Secrets live only in the OS
// credential store (macOS Keychain or the Linux Secret Service).
package cache

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	DefaultTTL = 7200
	MaxTTL     = 31536000
)

// DefaultConfig is written by InitConfig. Caching is off unless enabled is
// explicitly true: a cached password sits in a store that any process running
// as the user, including the harness, can read.
const DefaultConfig = "{\n  \"cache\": {\n    \"enabled\": false,\n    \"ttl_seconds\": 7200\n  }\n}\n"

// ErrConfig reports an invalid settings file. Authentication fails closed on it.
var ErrConfig = errors.New("invalid harness-root-hook config")

// ConfigPath resolves HARNESS_ROOT_HOOK_CONFIG, then XDG_CONFIG_HOME, then ~/.config.
func ConfigPath() (string, error) {
	if p := os.Getenv("HARNESS_ROOT_HOOK_CONFIG"); p != "" {
		return expandHome(p)
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return expandHome(filepath.Join(base, "harness-root-hook", "config.json"))
}

func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, p[1:]), nil
	}
	return p, nil
}

// LoadConfig returns the effective TTL in seconds (0 when caching is disabled).
// A missing file means the defaults (caching off). Anything unexpected is an error.
func LoadConfig(path string) (int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return ParseConfig(data)
}

// ParseConfig validates settings with the same strictness as the Python helper.
func ParseConfig(data []byte) (int, error) {
	top, err := object(data)
	if err != nil {
		return 0, fmt.Errorf("%w: config must be a JSON object", ErrConfig)
	}
	for key := range top {
		if key != "cache" {
			return 0, fmt.Errorf("%w: config must contain only a cache object", ErrConfig)
		}
	}
	enabled, ttl := false, DefaultTTL
	raw, ok := top["cache"]
	if !ok {
		return 0, nil
	}
	settings, err := object(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: cache must be an object", ErrConfig)
	}
	for key, value := range settings {
		switch key {
		case "enabled":
			v := string(bytes.TrimSpace(value))
			if v != "true" && v != "false" {
				return 0, fmt.Errorf("%w: cache.enabled must be boolean", ErrConfig)
			}
			enabled = v == "true"
		case "ttl_seconds":
			v := string(bytes.TrimSpace(value))
			n, err := strconv.Atoi(v)
			if err != nil || strings.HasPrefix(v, "+") || n < 0 || n > MaxTTL {
				return 0, fmt.Errorf("%w: cache.ttl_seconds must be an integer from 0 to %d", ErrConfig, MaxTTL)
			}
			ttl = n
		default:
			return 0, fmt.Errorf("%w: unknown cache setting", ErrConfig)
		}
	}
	if !enabled {
		return 0, nil
	}
	return ttl, nil
}

func object(data []byte) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("not an object")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// InitConfig creates the default settings file (mode 0600) when missing and
// validates, but never replaces, an existing one.
func InitConfig() (string, error) {
	path, err := ConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		_, err = LoadConfig(path)
		return path, err
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(DefaultConfig)
	return path, err
}
