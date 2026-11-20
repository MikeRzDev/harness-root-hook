package cache

import (
	"errors"
	"strings"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/sysbin"
)

// SecretService stores records in the desktop Secret Service via secret-tool.
// There is deliberately no file fallback.
type SecretService struct {
	Attributes []string
	Tool       string
	Exec       ExecFunc
}

// NewSecretService returns the Secret Service entry for harness.
func NewSecretService(harness string, run ExecFunc) *SecretService {
	return &SecretService{
		Attributes: []string{"application", "harness-root-hook", "harness", harness, "account", Account()},
		Tool:       sysbin.Find("secret-tool"),
		Exec:       run,
	}
}

func (s *SecretService) tool() (string, error) {
	if s.Tool == "" {
		return "", errors.New("secret-tool is not installed")
	}
	return s.Tool, nil
}

func (s *SecretService) Load() (*Record, error) {
	tool, err := s.tool()
	if err != nil {
		return nil, err
	}
	res, err := s.Exec(tool, append([]string{"lookup"}, s.Attributes...), nil)
	if err != nil {
		return nil, err
	}
	if res.Code == 1 && strings.TrimSpace(res.Stderr) == "" {
		return nil, nil // No matching item.
	}
	if res.Code != 0 {
		return nil, errors.New("could not read Secret Service cache")
	}
	return ParseRecord([]byte(res.Stdout)), nil
}

func (s *SecretService) Metadata() (*Meta, error) {
	r, err := s.Load()
	return r.Meta(), err
}

func (s *SecretService) Save(r Record) error {
	tool, err := s.tool()
	if err != nil {
		return err
	}
	args := append([]string{"store", "--label=Harness sudo password"}, s.Attributes...)
	res, err := s.Exec(tool, args, r.Encode())
	if err != nil || res.Code != 0 {
		return errors.New("could not store the password in Secret Service")
	}
	return nil
}

func (s *SecretService) Clear() error {
	tool, err := s.tool()
	if err != nil {
		return err
	}
	res, err := s.Exec(tool, append([]string{"clear"}, s.Attributes...), nil)
	if err != nil {
		return err
	}
	if res.Code != 0 && (res.Code != 1 || strings.TrimSpace(res.Stderr) != "") {
		return errors.New("could not clear Secret Service cache")
	}
	return nil
}
