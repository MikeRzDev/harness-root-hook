package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MikeRzDev/harness-root-hook/internal/jsonedit"
)

// readSettings loads a hooks settings file. A missing file is an empty object.
func readSettings(path string) (*jsonedit.Object, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return jsonedit.NewObject(), false, nil
	}
	if err != nil {
		return nil, false, err
	}
	v, err := jsonedit.Parse(data)
	if err != nil {
		return nil, true, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	root, ok := v.(*jsonedit.Object)
	if !ok {
		return nil, true, fmt.Errorf("%s must contain a JSON object", path)
	}
	if h, ok := root.Get("hooks"); ok {
		if _, ok := h.(*jsonedit.Object); !ok {
			return nil, true, fmt.Errorf("%s: hooks must be an object", path)
		}
	}
	return root, true, nil
}

// eventGroups returns the matcher groups for event, validating their shape.
func eventGroups(root *jsonedit.Object, event string) ([]any, error) {
	h, ok := root.Get("hooks")
	if !ok {
		return nil, nil
	}
	v, ok := h.(*jsonedit.Object).Get(event)
	if !ok {
		return nil, nil
	}
	groups, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("hooks.%s must be an array", event)
	}
	for _, g := range groups {
		obj, ok := g.(*jsonedit.Object)
		if !ok {
			return nil, fmt.Errorf("hooks.%s entries must be objects", event)
		}
		if hs, ok := obj.Get("hooks"); ok {
			if _, ok := hs.([]any); !ok {
				return nil, fmt.Errorf("hooks.%s entries must have a hooks array", event)
			}
		}
	}
	return groups, nil
}

// setEvent stores groups, pruning the event and the hooks object when empty.
func setEvent(root *jsonedit.Object, event string, groups []any) {
	h, ok := root.Get("hooks")
	if !ok {
		if len(groups) == 0 {
			return
		}
		h = jsonedit.NewObject()
		root.Set("hooks", h)
	}
	hooks := h.(*jsonedit.Object)
	if len(groups) == 0 {
		hooks.Delete(event)
		if hooks.Len() == 0 {
			root.Delete("hooks")
		}
		return
	}
	hooks.Set(event, groups)
}

func handlerCommand(h any) (string, bool) {
	obj, ok := h.(*jsonedit.Object)
	if !ok {
		return "", false
	}
	c, ok := obj.Get("command")
	s, isString := c.(string)
	return s, ok && isString
}

// removeHandlers drops handlers whose command matches and any group left empty by that.
func removeHandlers(groups []any, match func(string) bool) []any {
	var kept []any
	for _, g := range groups {
		obj := g.(*jsonedit.Object)
		hs, _ := obj.Get("hooks")
		handlers, _ := hs.([]any)
		var remaining []any
		for _, h := range handlers {
			if c, ok := handlerCommand(h); ok && match(c) {
				continue
			}
			remaining = append(remaining, h)
		}
		switch {
		case len(remaining) == len(handlers):
			kept = append(kept, g)
		case len(remaining) > 0:
			obj.Set("hooks", remaining)
			kept = append(kept, g)
		}
	}
	return kept
}

func hasHandler(groups []any, command string) bool {
	for _, g := range groups {
		hs, _ := g.(*jsonedit.Object).Get("hooks")
		handlers, _ := hs.([]any)
		for _, h := range handlers {
			if c, ok := handlerCommand(h); ok && c == command {
				return true
			}
		}
	}
	return false
}

func group(matcher, command string, timeout int) *jsonedit.Object {
	handler := jsonedit.NewObject()
	handler.Set("type", "command")
	handler.Set("command", command)
	if timeout > 0 {
		handler.Set("timeout", json.Number(fmt.Sprint(timeout)))
	}
	g := jsonedit.NewObject()
	if matcher != "" {
		g.Set("matcher", matcher)
	}
	g.Set("hooks", []any{handler})
	return g
}

// writeSettings replaces path atomically, keeping its permissions.
func writeSettings(path string, root *jsonedit.Object) error {
	data, err := jsonedit.Marshal(root)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
