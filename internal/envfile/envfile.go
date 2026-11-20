// Package envfile reads and writes values in a project's env file (.env.local
// or .env), and finds the env files of a project that git ignores. psudo uses
// only ignored files, so a value it saves cannot be committed by accident.
//
// An env file is plain text in the project folder: anything that can read the
// project, the agent included, can read it. It is for projects that already
// keep their secrets this way.
package envfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Names are the files psudo looks for, in order of preference.
var Names = []string{".env.local", ".env"}

// maxSize bounds the env files psudo is willing to parse.
const maxSize = 1 << 20

var keyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// Key is the variable an env file uses for a secret name: upper case, with
// "_" for "-". stripe-api-key is STRIPE_API_KEY. ok is false for a name that
// makes no valid variable, such as one that starts with a digit.
func Key(name string) (string, bool) {
	key := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	return key, keyRe.MatchString(key)
}

// Git answers the two questions psudo asks about a project.
type Git interface {
	// Root is the top folder of the work tree that contains dir.
	Root(dir string) (string, bool)
	// Ignored reports whether git ignores path, a file inside root. A file
	// git tracks is not ignored, whatever .gitignore says.
	Ignored(root, path string) bool
}

// Project is what Find learns about the folder a command runs in.
type Project struct {
	// Read lists the existing env files git ignores, in lookup order.
	Read []string
	// Save is where a new value goes: the first of Read, or else an env file
	// that does not exist yet but would be ignored. "" when there is none.
	Save string
	// Root is the top folder of the work tree.
	Root string
}

// regular reports whether path is an ordinary file. A symbolic link is not:
// psudo never follows one to a file outside the project.
func regular(path string) (exists, ok bool) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, true
	}
	if err != nil {
		return false, false
	}
	return true, info.Mode().IsRegular()
}

// insideRepo reports whether dir or a folder above it has a .git entry. Git
// itself is asked only then, so a folder that is no repository costs nothing.
func insideRepo(dir string) bool {
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// Find looks for the env files of the project that contains dir. It checks
// dir first and then the top of the work tree, so a package in a monorepo
// uses its own file. Without git, or outside a repository, it finds nothing.
func Find(dir string, git Git) Project {
	if git == nil {
		return Project{}
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || !filepath.IsAbs(real) || !insideRepo(real) {
		return Project{}
	}
	root, ok := git.Root(real)
	if !ok || !filepath.IsAbs(root) {
		return Project{}
	}
	p := Project{Root: root}
	dirs := []string{real}
	if root != real {
		dirs = append(dirs, root)
	}
	create := ""
	for _, d := range dirs {
		for _, name := range Names {
			path := filepath.Join(d, name)
			exists, ok := regular(path)
			if !ok || !git.Ignored(root, path) {
				continue
			}
			if exists {
				p.Read = append(p.Read, path)
			} else if create == "" {
				create = path
			}
		}
	}
	if len(p.Read) > 0 {
		p.Save = p.Read[0]
	} else {
		p.Save = create
	}
	return p
}

// entry is one assignment in an env file.
type entry struct{ key, value string }

func isKeyStart(c byte) bool { return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

func isKeyChar(c byte) bool { return isKeyStart(c) || c >= '0' && c <= '9' }

// parse reads the assignments of an env file: KEY=value, with an optional
// "export", a value in single quotes (literal), in double quotes (with \n, \",
// \\ and \$ escapes) or bare (up to a " #" comment). Quoted values may span
// lines. Lines it does not understand are skipped.
func parse(data []byte) []entry {
	var entries []entry
	for pos := 0; pos < len(data); {
		lineEnd := bytes.IndexByte(data[pos:], '\n')
		if lineEnd < 0 {
			lineEnd = len(data)
		} else {
			lineEnd += pos
		}
		next := min(lineEnd+1, len(data))
		i := pos
		skip := func() {
			for i < lineEnd && (data[i] == ' ' || data[i] == '\t') {
				i++
			}
		}
		skip()
		if bytes.HasPrefix(data[i:lineEnd], []byte("export")) && i+6 < lineEnd && (data[i+6] == ' ' || data[i+6] == '\t') {
			i += 6
			skip()
		}
		keyStart := i
		if i < lineEnd && isKeyStart(data[i]) {
			for i < lineEnd && isKeyChar(data[i]) {
				i++
			}
		}
		key := string(data[keyStart:i])
		skip()
		if key == "" || i >= lineEnd || data[i] != '=' {
			pos = next
			continue
		}
		i++
		skip()
		value, end, ok := "", next, false
		if i < lineEnd && (data[i] == '"' || data[i] == '\'') {
			value, end, ok = quoted(data, i)
		}
		if !ok {
			value, end = bare(string(data[i:lineEnd])), next
		}
		entries = append(entries, entry{key, value})
		pos = end
	}
	return entries
}

// quoted reads a quoted value that opens at data[at]. It returns the value
// and the offset after the line on which the closing quote stands.
func quoted(data []byte, at int) (string, int, bool) {
	quote := data[at]
	var b strings.Builder
	for i := at + 1; i < len(data); i++ {
		c := data[i]
		switch {
		case c == quote:
			end := bytes.IndexByte(data[i:], '\n')
			if end < 0 {
				return b.String(), len(data), true
			}
			return b.String(), i + end + 1, true
		case c == '\\' && quote == '"' && i+1 < len(data):
			i++
			switch data[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '"', '\\', '$':
				b.WriteByte(data[i])
			default:
				b.WriteByte('\\')
				b.WriteByte(data[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, false // the quote never closes
}

// bare is an unquoted value: up to a comment that follows a space.
func bare(s string) string {
	if i := strings.Index(s, " #"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "\t#"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, " \t\r")
}

func read(path string) ([]byte, error) {
	if exists, ok := regular(path); !ok {
		return nil, fmt.Errorf("%s is not a regular file", path)
	} else if !exists {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return os.ReadFile(path)
}

// Get returns the value of key in the env file at path. The last assignment
// wins, as it does for the programs that load these files.
func Get(path, key string) ([]byte, bool, error) {
	data, err := read(path)
	if err != nil {
		return nil, false, err
	}
	entries := parse(data)
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].key == key {
			return []byte(entries[i].value), true, nil
		}
	}
	return nil, false, nil
}

// Keys returns the variables assigned in the env file at path, in file order.
func Keys(path string) ([]string, error) {
	data, err := read(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var keys []string
	for _, e := range parse(data) {
		if !seen[e.key] {
			seen[e.key] = true
			keys = append(keys, e.key)
		}
	}
	return keys, nil
}

var plainValue = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]*$`)

// line renders one assignment. A value with special characters goes in single
// quotes, which every loader reads literally; one that contains a single
// quote or a line break goes in double quotes with escapes.
func line(key string, value []byte) string {
	v := string(value)
	switch {
	case plainValue.MatchString(v):
		return key + "=" + v + "\n"
	case !strings.ContainsAny(v, "'\n\r"):
		return key + "='" + v + "'\n"
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\n", `\n`, "\r", `\r`)
	return key + `="` + r.Replace(v) + "\"\n"
}

// Set stores key=value in the env file at path by adding one line at its end.
// The programs that load these files use the last assignment of a variable, so
// an earlier line for the same key (often an empty placeholder) loses to it.
// Nothing else in the file is rewritten, and no temporary copy of the file,
// which git might not ignore, is ever made. A new file gets mode 0600.
func Set(path, key string, value []byte) error {
	if !keyRe.MatchString(key) {
		return fmt.Errorf("%q is not a variable name", key)
	}
	if bytes.IndexByte(value, 0) >= 0 {
		return errors.New("the value contains a NUL byte")
	}
	data, err := read(path)
	if err != nil {
		return err
	}
	text := line(key, value)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		text = "\n" + text
	}
	// O_NOFOLLOW: a symbolic link at path is refused, never followed.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		f.Close()
		return fmt.Errorf("%s is not a regular file", path)
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
