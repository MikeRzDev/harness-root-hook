package cache

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const secret = `test-only 'password' \ $() with spaces`

func TestDefaultsAndExample(t *testing.T) {
	ttl, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || ttl != 7200 {
		t.Fatalf("ttl %d err %v", ttl, err)
	}
	example, err := os.ReadFile("../../config.example.json")
	if err != nil || string(example) != DefaultConfig {
		t.Fatalf("config.example.json differs from DefaultConfig: %v", err)
	}
}

func TestConfigOverridesAndDisable(t *testing.T) {
	for raw, want := range map[string]int{`{"cache":{"ttl_seconds":60}}`: 60, `{"cache":{"enabled":false}}`: 0,
		`{"cache":{"ttl_seconds":0}}`: 0, `{"cache":{}}`: 7200, `{}`: 7200} {
		if got, err := ParseConfig([]byte(raw)); err != nil || got != want {
			t.Errorf("%s: got %d err %v, want %d", raw, got, err, want)
		}
	}
}

func TestInvalidConfigFailsClosed(t *testing.T) {
	for _, raw := range []string{`{`, `[]`, `null`, `{"cache": null}`, `{"cache":{"ttl_seconds":-1}}`,
		`{"cache":{"ttl_seconds":true}}`, `{"cache":{"ttl_seconds":"7200"}}`, `{"cache":{"enabled":"false"}}`,
		`{"cache":{"enabled":null}}`, `{"cache":{"ttl_seconds":1.5}}`, `{"cache":{"ttl_seconds":1e3}}`,
		`{"cache":{"ttl_seconds":31536001}}`, `{"cache":{"ttl_second":7200}}`, `{"other": 1}`} {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
}

func TestInitPreservesCustomSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	t.Setenv("HARNESS_ROOT_HOOK_CONFIG", path)
	if _, err := InitConfig(); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	os.WriteFile(path, []byte(`{"cache":{"ttl_seconds":45}}`), 0o600)
	if _, err := InitConfig(); err != nil {
		t.Fatal(err)
	}
	if ttl, _ := LoadConfig(path); ttl != 45 {
		t.Fatalf("custom settings replaced: %d", ttl)
	}
	os.WriteFile(path, []byte(`{"cache":5}`), 0o600)
	if _, err := InitConfig(); err == nil {
		t.Fatal("invalid existing config accepted")
	}
}

func TestConfigPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HARNESS_ROOT_HOOK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", dir)
	if p, _ := ConfigPath(); p != filepath.Join(dir, "harness-root-hook", "config.json") {
		t.Fatalf("xdg path %s", p)
	}
	t.Setenv("HARNESS_ROOT_HOOK_CONFIG", "/explicit.json")
	if p, _ := ConfigPath(); p != "/explicit.json" {
		t.Fatalf("explicit path %s", p)
	}
}

func TestFreshFixedDeadline(t *testing.T) {
	m := &Meta{CreatedAt: 1000, TTLSeconds: 7200}
	for now, want := range map[float64]bool{1000: true, 8199: true, 8200: false, 999: false} {
		if Fresh(m, 7200, now) != want {
			t.Errorf("now %v: want %v", now, want)
		}
	}
	if Fresh(m, 60, 1060) || !Fresh(m, 60, 1059) {
		t.Error("reduced ttl not applied")
	}
	if Fresh(m, 20000, 8200) {
		t.Error("increased ttl extended an existing entry")
	}
	for _, bad := range []*Meta{nil, {CreatedAt: math.NaN(), TTLSeconds: 7200},
		{CreatedAt: math.Inf(1), TTLSeconds: 7200}, {CreatedAt: 1000, TTLSeconds: 0}} {
		if Fresh(bad, 7200, 1000) {
			t.Errorf("accepted %+v", bad)
		}
	}
	if Fresh(m, 0, 1001) {
		t.Error("disabled cache reported fresh")
	}
}

func TestParseRecordRejectsWrongTypes(t *testing.T) {
	if r := ParseRecord([]byte(`{"password":"p","created_at":1000.5,"ttl_seconds":7200}`)); r == nil || r.CreatedAt != 1000.5 {
		t.Fatalf("valid record rejected: %+v", r)
	}
	for _, raw := range []string{`nope`, `{"password":"p","created_at":"1000","ttl_seconds":7200}`,
		`{"password":"p","created_at":true,"ttl_seconds":7200}`, `{"password":"p","created_at":1,"ttl_seconds":1.5}`} {
		if ParseRecord([]byte(raw)) != nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

// fakeTools emulates security(1) and secret-tool, recording every argv.
type fakeTools struct {
	t      *testing.T
	stored []byte
	argv   [][]string
	stdin  [][]byte
}

var quotedWord = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

func (f *fakeTools) run(name string, args []string, stdin []byte) (Result, error) {
	f.argv = append(f.argv, append([]string{name}, args...))
	f.stdin = append(f.stdin, stdin)
	switch {
	case name == "secret-tool" && args[0] == "store":
		f.stored = stdin
	case name == "secret-tool" && args[0] == "clear":
		f.stored = nil
	case name == "secret-tool" && args[0] == "lookup":
		if f.stored == nil {
			return Result{Code: 1}, nil
		}
		return Result{Stdout: string(f.stored)}, nil
	case name == securityPath && args[0] == "-i":
		var words []string
		for _, m := range quotedWord.FindAllStringSubmatch(string(stdin), -1) {
			words = append(words, strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(m[1]))
		}
		for i, w := range words {
			if w == "-w" {
				f.stored, _ = base64.StdEncoding.DecodeString(words[i+1])
			}
		}
	case name == securityPath && args[0] == "delete-generic-password":
		f.stored = nil
	case name == securityPath && args[0] == "find-generic-password":
		if f.stored == nil {
			return Result{Code: 44}, nil
		}
		if args[len(args)-1] == "-w" {
			return Result{Stdout: base64.StdEncoding.EncodeToString(f.stored) + "\n"}, nil
		}
		r := ParseRecord(f.stored)
		return Result{Stdout: `    "icmt"<blob>="` + jsonFloat(r.CreatedAt) + " " + itoa(r.TTLSeconds) + `"`}, nil
	}
	return Result{}, nil
}

func jsonFloat(f float64) string { b, _ := json.Marshal(f); return string(b) }
func itoa(i int) string          { b, _ := json.Marshal(i); return string(b) }

func TestBackendsRoundTripWithoutSecretInArgv(t *testing.T) {
	for _, harness := range []string{"codex", "claude-code"} {
		tools := &fakeTools{t: t}
		ss := NewSecretService(harness, tools.run)
		ss.Tool = "secret-tool"
		for _, store := range []Store{NewKeychain(harness, tools.run), ss} {
			rec := Record{Password: secret, CreatedAt: 1000.25, TTLSeconds: 7200}
			if err := store.Save(rec); err != nil {
				t.Fatal(err)
			}
			got, err := store.Load()
			if err != nil || got == nil || *got != rec {
				t.Fatalf("%T load %+v err %v", store, got, err)
			}
			meta, _ := store.Metadata()
			if meta == nil || meta.CreatedAt != 1000.25 || meta.TTLSeconds != 7200 {
				t.Fatalf("%T metadata %+v", store, meta)
			}
			if err := store.Clear(); err != nil {
				t.Fatal(err)
			}
			if got, _ := store.Load(); got != nil {
				t.Fatalf("%T not cleared", store)
			}
		}
		encoded := base64.StdEncoding.EncodeToString(Record{Password: secret, CreatedAt: 1000.25, TTLSeconds: 7200}.Encode())
		for _, argv := range tools.argv {
			joined := strings.Join(argv, " ")
			if strings.Contains(joined, secret) || strings.Contains(joined, encoded) {
				t.Fatalf("secret in argv: %q", argv)
			}
			if !strings.Contains(joined, harness) && argv[1] != "-i" {
				t.Fatalf("entry not scoped to harness: %q", argv)
			}
		}
	}
}

func TestStoreErrorsDoNotFallBack(t *testing.T) {
	failing := func(string, []string, []byte) (Result, error) { return Result{Code: 2, Stderr: "unavailable"}, nil }
	ss := NewSecretService("codex", failing)
	ss.Tool = "secret-tool"
	for _, store := range []Store{NewKeychain("codex", failing), ss} {
		if store.Save(Record{Password: secret, CreatedAt: 1, TTLSeconds: 1}) == nil {
			t.Errorf("%T save error ignored", store)
		}
	}
	locked := func(string, []string, []byte) (Result, error) { return Result{Code: 1, Stderr: "locked"}, nil }
	ss = NewSecretService("codex", locked)
	ss.Tool = "secret-tool"
	if _, err := ss.Load(); err == nil {
		t.Error("Secret Service failure treated as a cache miss")
	}
}

func TestMalformedRecordIgnored(t *testing.T) {
	junk := func(string, []string, []byte) (Result, error) { return Result{Stdout: "not json/base64"}, nil }
	ss := NewSecretService("codex", junk)
	ss.Tool = "secret-tool"
	for _, store := range []Store{NewKeychain("codex", junk), ss} {
		if r, err := store.Load(); r != nil || err != nil {
			t.Errorf("%T: %+v %v", store, r, err)
		}
	}
}

func TestPurgeExpiredNeverReadsMacSecret(t *testing.T) {
	var argv [][]string
	run := func(name string, args []string, _ []byte) (Result, error) {
		argv = append(argv, args)
		return Result{Stdout: `"icmt"<blob>="1000 7200"`}, nil
	}
	if err := PurgeExpired(NewKeychain("codex", run), 7200, 8200); err != nil {
		t.Fatal(err)
	}
	for _, a := range argv {
		for _, w := range a {
			if w == "-w" {
				t.Fatalf("secret read during purge: %q", a)
			}
		}
	}
	if argv[len(argv)-1][0] != "delete-generic-password" {
		t.Fatalf("expired entry not deleted: %q", argv)
	}
}

func TestConcurrentLockSerialises(t *testing.T) {
	root := t.TempDir()
	var mu sync.Mutex
	inside, maxInside := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := LockIn(root, "codex")
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			maxInside = max(maxInside, inside)
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			unlock()
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("%d holders at once", maxInside)
	}
	filepath.Walk(root, func(p string, info os.FileInfo, _ error) error {
		if info.Mode().IsRegular() && info.Size() != 0 {
			t.Errorf("lock file %s is not empty", p)
		}
		return nil
	})
}

func TestLockRejectsSharedDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "harness-root-hook-locks-"+itoa(os.Getuid()))
	os.MkdirAll(dir, 0o755)
	os.Chmod(dir, 0o755)
	if _, err := LockIn(root, "codex"); err == nil {
		t.Fatal("group/world-accessible lock directory accepted")
	}
}

func TestReaperPlistAndScope(t *testing.T) {
	home := t.TempDir()
	var calls [][]string
	r := Reaper{Home: home, UID: 501, Exec: func(name string, args []string, _ []byte) (Result, error) {
		calls = append(calls, args)
		return Result{}, nil
	}}
	for _, h := range []string{"codex", "claude-code"} {
		if err := r.Install(h, "/opt/a & b/psudo", "/cfg/<x>.json"); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(home, "Library/LaunchAgents/com.harness-root-hook.codex.reaper.plist")
	data, _ := os.ReadFile(path)
	for _, want := range []string{"<integer>300</integer>", "/opt/a &amp; b/psudo", "--purge-expired=codex",
		"/cfg/&lt;x&gt;.json", "<key>HARNESS_ROOT_HOOK_CONFIG</key>"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("plist missing %q", want)
		}
	}
	r.Remove("codex")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("codex plist not removed")
	}
	if _, err := os.Stat(filepath.Join(home, "Library/LaunchAgents/com.harness-root-hook.claude-code.reaper.plist")); err != nil {
		t.Fatal("other harness plist removed")
	}
	if calls[1][0] != "bootstrap" || calls[1][1] != "gui/501" {
		t.Fatalf("launchctl calls %q", calls)
	}
}

func TestAccountResolvesWithoutCgo(t *testing.T) {
	if Account() == "" {
		t.Fatal("could not resolve the current user name")
	}
}
