package envfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestKey(t *testing.T) {
	for name, want := range map[string]string{"stripe-api-key": "STRIPE_API_KEY", "gh_token": "GH_TOKEN", "db2": "DB2"} {
		if got, ok := Key(name); !ok || got != want {
			t.Errorf("Key(%q) = %q %v", name, got, ok)
		}
	}
	if _, ok := Key("2fa-seed"); ok {
		t.Error("a name that starts with a digit made a variable")
	}
}

const sample = `# comment
PLAIN=abc123
export EXPORTED=yes
SPACED = spaced value   # trailing comment
EMPTY=
SINGLE='it is $literal \n'
DOUBLE="line1\nline2 \"q\" \$x \\"
MULTI="first
second"
not an assignment
1BAD=x
PLAIN=later-wins
URL=https://example.com/#fragment
`

func TestParse(t *testing.T) {
	got := map[string]string{}
	for _, e := range parse([]byte(sample)) {
		got[e.key] = e.value
	}
	want := map[string]string{
		"PLAIN": "later-wins", "EXPORTED": "yes", "SPACED": "spaced value", "EMPTY": "",
		"SINGLE": `it is $literal \n`, "DOUBLE": "line1\nline2 \"q\" $x \\", "MULTI": "first\nsecond",
		"URL": "https://example.com/#fragment",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// Windows line ends, no final newline, and a quote that never closes.
	got = map[string]string{}
	for _, e := range parse([]byte("A=1\r\nB='two'\r\nC=\"open\r\nD=4")) {
		got[e.key] = e.value
	}
	if got["A"] != "1" || got["B"] != "two" || got["C"] != `"open` || got["D"] != "4" {
		t.Fatalf("%q", got)
	}
}

func TestGetAndSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	if _, ok, err := Get(path, "TOKEN"); ok || err != nil {
		t.Fatalf("missing file: %v %v", ok, err)
	}
	// Every kind of value comes back exactly as it went in.
	values := []string{"simple-123", "with space", `quote ' and " and $HOME and \ back`, "two\nlines", "tab\there", "#hash", ""}
	for i, v := range values {
		key := "K" + string(rune('A'+i))
		if err := Set(path, key, []byte(v)); err != nil {
			t.Fatal(err)
		}
		got, ok, err := Get(path, key)
		if err != nil || !ok || string(got) != v {
			t.Errorf("%q came back as %q (%v %v)", v, got, ok, err)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	// A later value wins, and what was in the file stays as it was.
	os.WriteFile(path, []byte("# mine\nTOKEN=\nOTHER=keep"), 0o640)
	os.Chmod(path, 0o640)
	if err := Set(path, "TOKEN", []byte("s3cr3t value")); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "# mine\nTOKEN=\nOTHER=keep\nTOKEN='s3cr3t value'\n" {
		t.Fatalf("file %q", data)
	}
	if got, _, _ := Get(path, "TOKEN"); string(got) != "s3cr3t value" {
		t.Fatalf("got %q", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", info.Mode().Perm())
	}
	keys, _ := Keys(path)
	if !reflect.DeepEqual(keys, []string{"TOKEN", "OTHER"}) {
		t.Fatalf("keys %q", keys)
	}
	if err := Set(path, "bad key", []byte("x")); err == nil {
		t.Fatal("a bad variable name was written")
	}
}

// A symbolic link is never followed: the value could land outside the project.
func TestSymlinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte("TOKEN=old\n"), 0o644)
	link := filepath.Join(dir, ".env")
	os.Symlink(target, link)
	if err := Set(link, "TOKEN", []byte("new")); err == nil {
		t.Fatal("wrote through a symbolic link")
	}
	if _, _, err := Get(link, "TOKEN"); err == nil {
		t.Fatal("read through a symbolic link")
	}
	if data, _ := os.ReadFile(target); string(data) != "TOKEN=old\n" {
		t.Fatalf("target changed: %q", data)
	}
}

// fakeGit ignores exactly the listed paths.
type fakeGit struct {
	root    string
	ignored map[string]bool
}

func (g fakeGit) Root(string) (string, bool)  { return g.root, g.root != "" }
func (g fakeGit) Ignored(_, path string) bool { return g.ignored[path] }

func TestFind(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	pkg := filepath.Join(root, "packages", "api")
	os.MkdirAll(pkg, 0o755)
	os.Mkdir(filepath.Join(root, ".git"), 0o755)
	write := func(p string) { os.WriteFile(p, []byte("A=1\n"), 0o600) }
	rootEnv, rootLocal := filepath.Join(root, ".env"), filepath.Join(root, ".env.local")
	pkgEnv, pkgLocal := filepath.Join(pkg, ".env"), filepath.Join(pkg, ".env.local")

	// Nothing exists yet, but .env.local would be ignored: it is offered.
	git := fakeGit{root, map[string]bool{rootLocal: true, pkgLocal: true}}
	if p := Find(root, git); len(p.Read) != 0 || p.Save != rootLocal {
		t.Fatalf("%+v", p)
	}
	// A file git does not ignore (it would be committed) is never used.
	write(rootEnv)
	if p := Find(root, git); len(p.Read) != 0 || p.Save != rootLocal {
		t.Fatalf("unignored .env used: %+v", p)
	}
	// Existing ignored files are read; the folder of the command comes first.
	git.ignored[rootEnv] = true
	write(pkgLocal)
	p := Find(pkg, git)
	if !reflect.DeepEqual(p.Read, []string{pkgLocal, rootEnv}) || p.Save != pkgLocal || p.Root != root {
		t.Fatalf("%+v", p)
	}
	// A symbolic link is skipped even when git ignores it.
	os.Remove(pkgLocal)
	os.Symlink(rootEnv, pkgLocal)
	git.ignored[pkgEnv] = true
	if p := Find(pkg, git); !reflect.DeepEqual(p.Read, []string{rootEnv}) || p.Save != rootEnv {
		t.Fatalf("symlink: %+v", p)
	}
	// Outside a repository, or without git, there is nothing.
	if p := Find(t.TempDir(), git); p.Save != "" || len(p.Read) != 0 {
		t.Fatalf("no repository: %+v", p)
	}
	if p := Find(root, nil); p.Save != "" {
		t.Fatalf("no git: %+v", p)
	}
}

// The real git: an ignored file counts, a tracked or unignored one does not,
// and git settings from the caller's environment are not used.
func TestExecGit(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1"}
	run := func(args ...string) {
		cmd := exec.Command(gitPath, append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	os.WriteFile(filepath.Join(root, ".gitignore"), []byte(".env.local\n.env\n"), 0o644)
	os.WriteFile(filepath.Join(root, ".env"), []byte("TRACKED=1\n"), 0o644)
	os.WriteFile(filepath.Join(root, ".env.local"), []byte("TOKEN=abc\n"), 0o600)
	run("add", "-f", ".env", ".gitignore")
	run("commit", "-q", "-m", "init")

	git := ExecGit{Path: gitPath, Env: env}
	sub := filepath.Join(root, "sub")
	os.Mkdir(sub, 0o755)
	if got, ok := git.Root(sub); !ok || got != root {
		t.Fatalf("root %q %v", got, ok)
	}
	if !git.Ignored(root, filepath.Join(root, ".env.local")) {
		t.Error(".env.local is not reported as ignored")
	}
	if git.Ignored(root, filepath.Join(root, ".env")) {
		t.Error("a tracked .env is reported as ignored")
	}
	if git.Ignored(root, filepath.Join(root, "README.md")) {
		t.Error("an unignored file is reported as ignored")
	}
	p := Find(sub, git)
	if !reflect.DeepEqual(p.Read, []string{filepath.Join(root, ".env.local")}) || !strings.HasSuffix(p.Save, ".env.local") {
		t.Fatalf("%+v", p)
	}
	if _, ok := git.Root(t.TempDir()); ok {
		t.Error("a folder outside any repository has a root")
	}
}
