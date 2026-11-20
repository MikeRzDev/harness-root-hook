package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/MikeRzDev/harness-psudo-hook/internal/jsonedit"
	"github.com/MikeRzDev/harness-psudo-hook/internal/shquote"
)

// SuggestedRule is the rule psudo offers when a request names a secret that
// has no rule: only this program, only this host. Like any rule it does not
// ask before each use; the dialog in which the user accepts it is the question.
//
// The rule also names the variables the request puts the secret called name
// in, so that later requests cannot move it to another variable.
func SuggestedRule(req Request, name string) Rule {
	r := Rule{Commands: []string{req.Argv[0]}, Local: req.Host == ""}
	if req.Host != "" {
		r.SSHHosts = []string{req.Host}
	}
	for _, u := range req.Uses {
		if u.Name == name && !slices.Contains(r.Vars, u.Var) {
			r.Vars = append(r.Vars, u.Var)
		}
	}
	return r
}

// AddRules writes rules into the "secrets" object of the config file at
// path, keeping the order and formatting of everything else. Existing rules
// with the same names are not replaced.
func AddRules(path string, rules map[string]Rule) error {
	root := jsonedit.NewObject()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		v, err := jsonedit.Parse(data)
		obj, ok := v.(*jsonedit.Object)
		if err != nil || !ok {
			return fmt.Errorf("%s is not a JSON object", path)
		}
		root = obj
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	secrets := jsonedit.NewObject()
	if v, ok := root.Get("secrets"); ok {
		obj, ok := v.(*jsonedit.Object)
		if !ok {
			return fmt.Errorf("%s: secrets is not an object", path)
		}
		secrets = obj
	}
	for _, name := range sortedNames(rules) {
		if _, exists := secrets.Get(name); exists {
			return fmt.Errorf("%s already has a rule for %q", path, name)
		}
		r := rules[name]
		entry := jsonedit.NewObject()
		cmds := make([]any, len(r.Commands))
		for i, c := range r.Commands {
			cmds[i] = c
		}
		entry.Set("commands", cmds)
		if len(r.Vars) > 0 {
			vars := make([]any, len(r.Vars))
			for i, v := range r.Vars {
				vars[i] = v
			}
			entry.Set("vars", vars)
		}
		if !r.Local {
			entry.Set("local", false)
		}
		if len(r.SSHHosts) > 0 {
			hosts := make([]any, len(r.SSHHosts))
			for i, h := range r.SSHHosts {
				hosts[i] = h
			}
			entry.Set("ssh_hosts", hosts)
		}
		secrets.Set(name, entry)
	}
	root.Set("secrets", secrets)
	out, err := jsonedit.Marshal(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// merge returns p with extra added.
func merge(p Policy, extra map[string]Rule) Policy {
	out := Policy{}
	for k, v := range p {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func ruleNote(path, name string, r Rule) string {
	where := "on this computer"
	if !r.Local {
		where = "on " + strings.Join(r.SSHHosts, ", ")
	}
	if path == "" {
		path = "config.json"
	}
	return "This also adds a rule to " + shquote.VisibleLine(path) + ": " + strings.Join(r.Commands, ", ") +
		" may use \"" + name + "\" as " + strings.Join(r.Vars, ", ") + " " + where +
		". From then on psudo gives it the secret without asking again; any other program or variable is refused."
}
