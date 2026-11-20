package vault

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/MikeRzDev/harness-psudo-hook/internal/cache"
)

// fakeSecurity models security(1): items keyed by service, `-i` commands
// parsed from stdin, exit 44 for a missing item.
type fakeSecurity struct {
	items map[string]string
	argv  [][]string
	lines []string
}

func unquote(line string) []string {
	var out []string
	for i := 0; i < len(line); i++ {
		if line[i] != '"' {
			continue
		}
		var b strings.Builder
		for i++; i < len(line) && line[i] != '"'; i++ {
			if line[i] == '\\' {
				i++
			}
			b.WriteByte(line[i])
		}
		out = append(out, b.String())
	}
	return out
}

func arg(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeSecurity) exec(name string, args []string, stdin []byte) (cache.Result, error) {
	f.argv = append(f.argv, args)
	if args[0] == "-i" {
		line := strings.TrimSuffix(string(stdin), "\n")
		f.lines = append(f.lines, line)
		if len(line) >= 4096 {
			return cache.Result{Code: 1}, nil
		}
		args = unquote(line)
	}
	svc := arg(args, "-s")
	switch args[0] {
	case "add-generic-password":
		f.items[svc] = arg(args, "-w")
	case "find-generic-password":
		v, ok := f.items[svc]
		if !ok {
			return cache.Result{Code: 44}, nil
		}
		if args[len(args)-1] == "-w" {
			return cache.Result{Stdout: v + "\n"}, nil
		}
		return cache.Result{Stdout: `"svce"<blob>="` + svc + `"`}, nil
	case "delete-generic-password":
		if _, ok := f.items[svc]; !ok {
			return cache.Result{Code: 44}, nil
		}
		delete(f.items, svc)
	case "dump-keychain":
		var b strings.Builder
		for s := range f.items {
			b.WriteString(`    "svce"<blob>="` + s + "\"\n")
		}
		b.WriteString(`    "svce"<blob>="harness-root-hook.claude-code"` + "\n")
		return cache.Result{Stdout: b.String()}, nil
	}
	return cache.Result{}, nil
}

func roundTrip(t *testing.T, v Vault) {
	t.Helper()
	big := bytes.Repeat([]byte("line with \"quotes\" and \\ and $(x)\n"), 400) // ~14 KB
	for name, value := range map[string][]byte{"small": []byte(`a "b" \c`), "big": big} {
		if err := v.Put(name, value); err != nil {
			t.Fatal(err)
		}
		got, err := v.Get(name)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("%s: %v %q", name, err, got[:min(len(got), 40)])
		}
		if ok, err := v.Has(name); !ok || err != nil {
			t.Fatalf("has %s", name)
		}
	}
	if got, err := v.List(); err != nil || !reflect.DeepEqual(got, []string{"big", "small"}) {
		t.Fatalf("list %v %v", got, err)
	}
	// Shrinking a value must not leave stale parts behind.
	if err := v.Put("big", []byte("short")); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("big"); string(got) != "short" {
		t.Fatalf("shrunk %q", got)
	}
	if err := v.Delete("big"); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete("big"); err != nil {
		t.Fatal("deleting a missing entry", err)
	}
	if got, err := v.Get("big"); got != nil || err != nil {
		t.Fatalf("deleted %q %v", got, err)
	}
	if ok, _ := v.Has("big"); ok {
		t.Fatal("has deleted")
	}
}

func TestKeychain(t *testing.T) {
	f := &fakeSecurity{items: map[string]string{}}
	k := &Keychain{Kind: "secret", Account: "me", Exec: f.exec}
	roundTrip(t, k)
	k.Delete("small")
	for _, s := range f.items {
		t.Fatalf("left behind %q", s)
	}
	// The value only ever travels on stdin, never in argv.
	for _, a := range f.argv {
		for _, x := range a {
			if strings.Contains(x, "quotes") || strings.Contains(x, "YSAiYiIgXGM") {
				t.Fatalf("value in argv %q", a)
			}
		}
	}
	for _, l := range f.lines {
		if len(l) >= 4096 {
			t.Fatal("security -i line over its limit")
		}
	}
	f.items["harness-root-hook.secret.bad"] = "x"
	if _, err := k.Get("bad"); err == nil {
		t.Fatal("malformed entry accepted")
	}
}

// fakeSecretTool models secret-tool with items keyed by their name attribute.
type fakeSecretTool struct{ items map[string]string }

func (f *fakeSecretTool) exec(name string, args []string, stdin []byte) (cache.Result, error) {
	n := arg(args, "name")
	switch args[0] {
	case "store":
		f.items[n] = string(stdin)
	case "lookup":
		v, ok := f.items[n]
		if !ok {
			return cache.Result{Code: 1}, nil
		}
		return cache.Result{Stdout: v}, nil
	case "clear":
		delete(f.items, n)
	case "search":
		var b strings.Builder
		for k, v := range f.items {
			b.WriteString("[/1]\nlabel = psudo secret " + k + "\nsecret = " + v + "\nattribute.name = " + k + "\n")
		}
		return cache.Result{Stdout: b.String()}, nil
	}
	return cache.Result{}, nil
}

func TestSecretService(t *testing.T) {
	f := &fakeSecretTool{items: map[string]string{}}
	roundTrip(t, &SecretService{Kind: "secret", Account: "me", Tool: "/usr/bin/secret-tool", Exec: f.exec})
	if _, err := (&SecretService{Kind: "secret"}).Get("x"); err == nil {
		t.Fatal("missing secret-tool")
	}
}
