package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/MikeRzDev/harness-psudo-hook/internal/vault"
)

// Key identifies a request exactly: a remembered approval covers only the
// same harness, host, folder, secrets, variables and command.
func Key(harness string, req Request) string {
	data, _ := json.Marshal([]any{harness, req.Host, req.Dir, req.Uses, req.Argv})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Approvals are remembered "Allow for N min" answers, stored in the
// credential store as one entry per harness: a map from Key to expiry (Unix
// seconds). They hold no secret values.
type Approvals struct {
	Vault   vault.Vault
	Harness string
	Lock    func() (func(), error)
	Now     func() time.Time
}

func (a *Approvals) load() (map[string]int64, error) {
	data, err := a.Vault.Get(a.Harness)
	if err != nil {
		return nil, err
	}
	m := map[string]int64{}
	if data != nil && json.Unmarshal(data, &m) != nil {
		m = map[string]int64{} // a damaged entry approves nothing
	}
	return m, nil
}

// Has reports whether key has an approval that has not expired.
func (a *Approvals) Has(key string) (bool, error) {
	m, err := a.load()
	if err != nil {
		return false, err
	}
	return m[key] > a.Now().Unix(), nil
}

// Add remembers key for d, dropping expired approvals.
func (a *Approvals) Add(key string, d time.Duration) error {
	unlock, err := a.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := a.load()
	if err != nil {
		return err
	}
	now := a.Now().Unix()
	for k, until := range m {
		if until <= now {
			delete(m, k)
		}
	}
	m[key] = now + int64(d/time.Second)
	data, _ := json.Marshal(m)
	return a.Vault.Put(a.Harness, data)
}

// Clear forgets every approval.
func (a *Approvals) Clear() error { return a.Vault.Delete(a.Harness) }

// RulesHash is the SHA-256 of the policy. The rules live in a file the agent
// can edit, so psudo uses them only after the user approves this hash.
func RulesHash(p Policy) string {
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

const rulesEntry = "rules"

// RulesApproved reports whether the user approved exactly these rules.
func (a *Approvals) RulesApproved(hash string) (bool, error) {
	data, err := a.Vault.Get(rulesEntry)
	if err != nil {
		return false, err
	}
	return data != nil && string(data) == hash, nil
}

// ApproveRules records the user's approval of the rules with this hash.
func (a *Approvals) ApproveRules(hash string) error { return a.Vault.Put(rulesEntry, []byte(hash)) }
