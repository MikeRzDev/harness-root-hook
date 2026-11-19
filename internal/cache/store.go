package cache

import (
	"errors"
	"os"
	"os/user"
	"runtime"
)

// Store is an OS credential-store entry for one harness.
type Store interface {
	// Metadata returns non-secret timestamps, or nil when there is no entry.
	Metadata() (*Meta, error)
	// Load returns the full record, or nil when missing or malformed.
	Load() (*Record, error)
	Save(Record) error
	Clear() error
}

// ErrUnsupported is returned on operating systems other than macOS and Linux.
var ErrUnsupported = errors.New("only Linux and macOS are supported")

// Account is the current user's login name.
func Account() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// NewStore returns the platform credential store for harness.
func NewStore(harness string) (Store, error) {
	switch runtime.GOOS {
	case "darwin":
		return NewKeychain(harness, Run), nil
	case "linux":
		return NewSecretService(harness, Run), nil
	}
	return nil, ErrUnsupported
}

// PurgeExpired deletes the entry when it is no longer fresh, without reading
// the secret on macOS.
func PurgeExpired(s Store, ttl int, now float64) error {
	meta, err := s.Metadata()
	if err != nil {
		return err
	}
	if !Fresh(meta, ttl, now) {
		return s.Clear()
	}
	return nil
}
