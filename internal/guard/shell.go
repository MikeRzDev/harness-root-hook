package guard

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// The guard reads a Bash command the way the shell would, closely enough to
// tell where sudo or sshpass would actually run from where the word is only
// data (a heredoc written to a file, a commit message, a grep pattern). It is
// best effort, like the spec says: anything it cannot parse falls back to the
// plain word match, so a parse failure denies rather than allows.

// verdict is what a command does that the guard cares about.
type verdict int

const (
	allow verdict = iota
	denyRoot
	denyCache
)

func worse(a, b verdict) verdict {
	if b > a {
		return b
	}
	return a
}

// word is one shell word after quote removal. Expansions stay in the text as
// written ($x, $(…)), and dynamic records that one was present.
type word struct {
	text    string
	dynamic bool
	opaque  bool // contains $'…', whose text cannot be judged
}

type heredoc struct {
	body    string
	literal bool // quoted delimiter: no expansions in the body
}

type simpleCmd struct {
	words    []word
	heredocs []*heredoc
	herestr  []string
}

type pipeline struct{ cmds []*simpleCmd }

type pendingDoc struct {
	cmd   *simpleCmd
	delim string
	strip bool // <<-
	lit   bool
}

type parser struct {
	src     string
	i       int
	depth   int
	self    string
	bad     bool
	nested  verdict // from command substitutions
	pipes   []*pipeline
	pipe    *pipeline
	cmd     *simpleCmd
	pending []pendingDoc
}

const maxDepth = 16

var (
	cacheTools = map[string]bool{"security": true, "secret-tool": true}
	// Programs whose arguments, here-docs or stdin are shell code.
	carriers = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true,
		"fish": true, "ssh": true, "eval": true, "su": true, "source": true, ".": true}
	// Programs that run another program given as a later argument.
	wrappers = map[string]bool{"env": true, "nohup": true, "time": true, "exec": true, "command": true,
		"builtin": true, "nice": true, "ionice": true, "xargs": true, "timeout": true, "stdbuf": true,
		"caffeinate": true, "watch": true, "chrt": true, "taskset": true, "unbuffer": true, "doas": true,
		"find": true, "setsid": true, "flock": true, "parallel": true, "script": true, "runuser": true,
		"chroot": true, "nsenter": true, "unshare": true, "systemd-run": true, "sg": true, "strace": true,
		"ltrace": true, "arch": true, "nohup.exe": true}
	// Interpreters: their arguments, here-docs and stdin are code too.
	interpreter = regexp.MustCompile(`^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|deno|bun|php[0-9.]*|` +
		`[gmn]?awk|osascript|expect|tclsh|wish|lua[0-9.]*|Rscript|pwsh|swift|groovy|jshell|irb)$`)
	// Programs that only read or write data. For these alone, the word "sudo"
	// in an argument or here-document is text. Every other program is judged
	// on its full text, so an unknown program fails closed.
	dataCommands = map[string]bool{"cat": true, "tee": true, "echo": true, "printf": true, "grep": true,
		"egrep": true, "fgrep": true, "rg": true, "ag": true, "ack": true, "git": true, "gh": true, "ls": true,
		"head": true, "tail": true, "wc": true, "diff": true, "cmp": true, "less": true, "more": true,
		"mkdir": true, "cp": true, "mv": true, "rm": true, "touch": true, "ln": true, "chmod": true, "jq": true,
		"yq": true, "sort": true, "uniq": true, "cut": true, "tr": true, "column": true, "test": true, "[": true,
		"true": true, "false": true, "stat": true, "file": true, "basename": true, "dirname": true,
		"realpath": true, "readlink": true, "pwd": true, "cd": true, "man": true, "which": true, "type": true}
	reserved = map[string]bool{"!": true, "{": true, "}": true, "if": true, "then": true, "else": true,
		"elif": true, "fi": true, "do": true, "done": true, "while": true, "until": true, "function": true}
	assignment   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=`)
	cachePattern = regexp.MustCompile(`harness-root-hook`)
	cacheToolPat = regexp.MustCompile(`(^|[^A-Za-z0-9_-])(security|secret-tool)([^A-Za-z0-9_-]|$)`)
	caseWord     = regexp.MustCompile(`(^|[^A-Za-z0-9_])case([^A-Za-z0-9_]|$)`)
)

// textVerdict is the plain-text rule, used for code the guard does not parse
// (an argument of sh -c or ssh) and as the fail-closed fallback.
func textVerdict(s string) verdict {
	v := allow
	if pattern.MatchString(s) {
		v = denyRoot
	}
	if cachePattern.MatchString(s) && cacheToolPat.MatchString(s) {
		v = worse(v, denyCache)
	}
	return v
}

// judge reports what a Bash command would do that psudo's guard denies.
// self is the installed psudo; only that binary's arguments are trusted.
func judge(command, self string) verdict { return decideDepth(command, 0, self) }

func decideDepth(command string, depth int, self string) verdict {
	if depth > maxDepth {
		return textVerdict(command)
	}
	p := &parser{src: command, depth: depth, self: self}
	p.parse()
	if p.bad {
		return textVerdict(command)
	}
	v := p.nested
	for _, pl := range p.pipes {
		v = worse(v, pl.verdict(command, self))
	}
	return v
}

func (p *parser) eof() bool { return p.i >= len(p.src) }

func (p *parser) endCmd() {
	if p.cmd != nil && (len(p.cmd.words) > 0 || len(p.cmd.heredocs) > 0 || len(p.cmd.herestr) > 0) {
		if p.pipe == nil {
			p.pipe = &pipeline{}
		}
		p.pipe.cmds = append(p.pipe.cmds, p.cmd)
	}
	p.cmd = nil
}

func (p *parser) endPipe() {
	p.endCmd()
	if p.pipe != nil {
		p.pipes = append(p.pipes, p.pipe)
	}
	p.pipe = nil
}

func (p *parser) current() *simpleCmd {
	if p.cmd == nil {
		p.cmd = &simpleCmd{}
	}
	return p.cmd
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

func isOp(c byte) bool { return strings.IndexByte(";&|()<>", c) >= 0 }

func (p *parser) parse() {
	atWordStart := true
	for !p.eof() && !p.bad {
		c := p.src[p.i]
		switch {
		case isBlank(c):
			p.i++
			atWordStart = true
			continue
		case c == '\\' && p.i+1 < len(p.src) && p.src[p.i+1] == '\n':
			p.i += 2
			continue
		case c == '#' && atWordStart:
			for !p.eof() && p.src[p.i] != '\n' {
				p.i++
			}
			continue
		case c == '\n':
			p.i++
			p.endPipe()
			p.readHeredocs()
		case c == '|':
			p.i++
			if !p.eof() && p.src[p.i] == '|' {
				p.i++
				p.endPipe()
			} else {
				if !p.eof() && p.src[p.i] == '&' {
					p.i++
				}
				p.endCmd()
			}
		case c == '&' && p.i+1 < len(p.src) && p.src[p.i+1] == '>':
			p.i += 2
			if !p.eof() && p.src[p.i] == '>' {
				p.i++
			}
			p.redirectTarget()
		case c == ';' || c == '&' || c == '(' || c == ')':
			p.i++
			for !p.eof() && (p.src[p.i] == ';' || p.src[p.i] == '&') && (c == ';' || c == '&') {
				p.i++
			}
			p.endPipe()
		case c == '<' || c == '>':
			p.redirect()
		case c >= '0' && c <= '9' && p.fdRedirect():
			// digits were part of a redirection such as 2>/dev/null
		default:
			w := p.word()
			if p.bad {
				return
			}
			cmd := p.current()
			cmd.words = append(cmd.words, w)
		}
		atWordStart = true
	}
	if p.bad {
		return
	}
	p.endPipe()
	if len(p.pending) > 0 {
		p.bad = true // here-document never started
	}
}

// fdRedirect consumes "N>" or "N<" when the digits run straight into it.
func (p *parser) fdRedirect() bool {
	j := p.i
	for j < len(p.src) && p.src[j] >= '0' && p.src[j] <= '9' {
		j++
	}
	if j < len(p.src) && (p.src[j] == '<' || p.src[j] == '>') {
		p.i = j
		p.redirect()
		return true
	}
	return false
}

func (p *parser) redirect() {
	start := p.i
	for !p.eof() && strings.IndexByte("<>&|-", p.src[p.i]) >= 0 && p.i-start < 3 {
		if p.src[p.i] == '-' && !strings.HasPrefix(p.src[start:], "<<") {
			break
		}
		p.i++
	}
	op := p.src[start:p.i]
	switch {
	case strings.HasPrefix(op, "<<<"):
		w := p.nextWord()
		cmd := p.current()
		cmd.herestr = append(cmd.herestr, w.text)
	case strings.HasPrefix(op, "<<"):
		p.skipBlanks()
		lit := false
		raw := p.i
		w := p.word()
		if strings.ContainsAny(p.src[raw:p.i], `'"\`) {
			lit = true
		}
		if w.text == "" {
			p.bad = true
			return
		}
		cmd := p.current()
		p.pending = append(p.pending, pendingDoc{cmd: cmd, delim: w.text, strip: op == "<<-", lit: lit})
	case strings.HasSuffix(op, "&"):
		p.redirectTarget() // >&2 or <&0: the target is a descriptor or a file
	default:
		p.redirectTarget()
	}
}

func (p *parser) skipBlanks() {
	for !p.eof() && isBlank(p.src[p.i]) {
		p.i++
	}
}

// redirectTarget reads the file word after a redirection. It is not an
// argument, but substitutions inside it still run.
func (p *parser) redirectTarget() { p.nextWord() }

func (p *parser) nextWord() word {
	p.skipBlanks()
	if p.eof() || isOp(p.src[p.i]) || p.src[p.i] == '\n' {
		return word{}
	}
	return p.word()
}

func (p *parser) readHeredocs() {
	for _, d := range p.pending {
		var body strings.Builder
		found := false
		for !p.eof() {
			end := strings.IndexByte(p.src[p.i:], '\n')
			line := ""
			if end < 0 {
				line, p.i = p.src[p.i:], len(p.src)
			} else {
				line, p.i = p.src[p.i:p.i+end], p.i+end+1
			}
			cmp := line
			if d.strip {
				cmp = strings.TrimLeft(line, "\t")
			}
			if cmp == d.delim {
				found = true
				break
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		if !found {
			p.bad = true
			return
		}
		doc := &heredoc{body: body.String(), literal: d.lit}
		d.cmd.heredocs = append(d.cmd.heredocs, doc)
		if !doc.literal {
			p.scanExpansions(doc.body)
		}
	}
	p.pending = nil
}

// scanExpansions checks command substitutions in text the shell expands but
// does not split into words (an unquoted here-document body).
func (p *parser) scanExpansions(s string) {
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			i++
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '(':
			end, ok := matchParen(s, i+2)
			if !ok {
				p.bad = true
				return
			}
			p.substitute(s[i+2 : end])
			i = end
		case s[i] == '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				p.bad = true
				return
			}
			p.substitute(strings.ReplaceAll(s[i+1:i+1+end], "\\`", "`"))
			i += end + 1
		}
	}
}

func (p *parser) substitute(code string) {
	p.nested = worse(p.nested, decideDepth(code, p.depth+1, p.self))
}

// matchParen returns the index of the ")" closing a "(" just before start.
func matchParen(s string, start int) (int, bool) {
	depth := 1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return 0, false
			}
			i += end + 1
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
			if i >= len(s) {
				return 0, false
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// word reads one word, removing quotes and checking substitutions.
func (p *parser) word() word {
	var b strings.Builder
	w := word{}
	for !p.eof() {
		c := p.src[p.i]
		if isBlank(c) || c == '\n' || isOp(c) {
			break
		}
		switch c {
		case '\'':
			end := strings.IndexByte(p.src[p.i+1:], '\'')
			if end < 0 {
				p.bad = true
				return w
			}
			b.WriteString(p.src[p.i+1 : p.i+1+end])
			p.i += end + 2
		case '"':
			p.i++
			for !p.eof() && p.src[p.i] != '"' {
				d := p.src[p.i]
				switch {
				case d == '\\' && p.i+1 < len(p.src) && strings.IndexByte("$`\"\\\n", p.src[p.i+1]) >= 0:
					if p.src[p.i+1] != '\n' {
						b.WriteByte(p.src[p.i+1])
					}
					p.i += 2
				case d == '$' || d == '`':
					p.expansion(&b, &w)
				default:
					b.WriteByte(d)
					p.i++
				}
				if p.bad {
					return w
				}
			}
			if p.eof() {
				p.bad = true
				return w
			}
			p.i++
		case '\\':
			if p.i+1 < len(p.src) {
				if p.src[p.i+1] != '\n' {
					b.WriteByte(p.src[p.i+1])
				}
				p.i += 2
			} else {
				p.i++
			}
		case '$', '`':
			p.expansion(&b, &w)
		default:
			b.WriteByte(c)
			p.i++
		}
		if p.bad {
			return w
		}
	}
	w.text = b.String()
	return w
}

// expansion consumes $…, ${…}, $(…), $((…)) or `…` at p.i.
func (p *parser) expansion(b *strings.Builder, w *word) {
	w.dynamic = true
	s := p.src
	if s[p.i] == '`' {
		end := strings.IndexByte(s[p.i+1:], '`')
		for end >= 0 && s[p.i+end] == '\\' { // an escaped backtick inside
			next := strings.IndexByte(s[p.i+end+2:], '`')
			if next < 0 {
				end = -1
				break
			}
			end += next + 1
		}
		if end < 0 {
			p.bad = true
			return
		}
		p.substitute(strings.ReplaceAll(s[p.i+1:p.i+1+end], "\\`", "`"))
		b.WriteString(s[p.i : p.i+end+2])
		p.i += end + 2
		return
	}
	if p.i+1 >= len(s) {
		b.WriteByte('$')
		p.i++
		return
	}
	switch s[p.i+1] {
	case '(':
		end, ok := matchParen(s, p.i+2)
		if !ok {
			p.bad = true
			return
		}
		if strings.HasPrefix(s[p.i:], "$((") {
			// Arithmetic: not a command, but $(…) inside it still runs.
			p.scanExpansions(s[p.i+2 : end])
		} else {
			inner := s[p.i+2 : end]
			if caseWord.MatchString(inner) {
				// case patterns end in ")", which this matcher cannot pair
				// reliably: deny rather than misread where the code ends.
				p.nested = worse(p.nested, denyRoot)
			}
			p.substitute(inner)
		}
		b.WriteString(s[p.i : end+1])
		p.i = end + 1
	case '{':
		end := strings.IndexByte(s[p.i:], '}')
		if end < 0 {
			p.bad = true
			return
		}
		// ${x:-$(…)} and similar run their command substitutions.
		p.scanExpansions(s[p.i+2 : p.i+end])
		b.WriteString(s[p.i : p.i+end+1])
		p.i += end + 1
	case '\'':
		// $'…' (ANSI-C quoting) can spell any word in escapes, so its
		// content cannot be judged as text.
		w.opaque = true
		j := p.i + 2
		for j < len(s) && s[j] != '\'' {
			if s[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(s) {
			p.bad = true
			return
		}
		b.WriteString(s[p.i : j+1])
		p.i = j + 1
	default:
		b.WriteByte('$')
		p.i++
	}
}

func base(s string) string { return path.Base(s) }

// commandWord returns the index of the program a simple command runs,
// skipping assignments and reserved words, or -1.
func commandWord(words []word, from int) int {
	for k := from; k < len(words); k++ {
		t := words[k].text
		if reserved[t] || assignment.MatchString(t) {
			continue
		}
		return k
	}
	return -1
}

func (pl *pipeline) verdict(full, self string) verdict {
	v := allow
	carrierInPipe := false
	for _, c := range pl.cmds {
		cv, carrier := c.verdict(full, self)
		v = worse(v, cv)
		carrierInPipe = carrierInPipe || carrier
	}
	if carrierInPipe {
		// Data piped into a shell or ssh is code.
		for _, c := range pl.cmds {
			v = worse(v, c.textVerdict())
		}
	}
	return v
}

func (c *simpleCmd) textVerdict() verdict {
	v := allow
	for _, w := range c.words {
		v = worse(v, wordVerdict(w))
	}
	for _, d := range c.heredocs {
		v = worse(v, textVerdict(d.body))
	}
	for _, h := range c.herestr {
		v = worse(v, textVerdict(h))
	}
	return v
}

// verdict judges one simple command and reports whether it runs shell code
// taken from its arguments or stdin.
func (c *simpleCmd) verdict(full, self string) (verdict, bool) {
	k := commandWord(c.words, 0)
	if k < 0 {
		return allow, false
	}
	for {
		cw := c.words[k]
		name := base(cw.text)
		switch {
		case name == "sudo" || name == "sshpass":
			return denyRoot, false
		case name == "psudo" && isSelf(cw.text, self):
			// The real psudo runs its arguments as root; sudo inside is harmless.
			return allow, false
		case cw.dynamic || cw.opaque:
			// The program is computed ($cmd, ${x:-…}, $'\x..'): it cannot be
			// judged, so deny.
			return denyRoot, true
		case cacheTools[name]:
			for _, w := range c.words[k+1:] {
				if cachePattern.MatchString(w.text) {
					return denyCache, false
				}
			}
			return allow, false
		case carriers[name] || interpreter.MatchString(name):
			return c.textVerdict(), true
		case wrappers[name]:
			// Any later word that names sudo or sshpass is what it runs.
			for _, w := range c.words[k+1:] {
				if n := base(w.text); n == "sudo" || n == "sshpass" {
					return denyRoot, false
				}
			}
			next := k + 1
			for next < len(c.words) && (strings.HasPrefix(c.words[next].text, "-") || assignment.MatchString(c.words[next].text)) {
				next++
			}
			if next >= len(c.words) {
				return allow, false
			}
			k = next
			continue
		case dataCommands[name]:
			return c.dataVerdict(name, k), false
		}
		// Unknown program: fail closed on its full text.
		return c.textVerdict(), false
	}
}

// wordVerdict judges one word as text; $'…' content cannot be judged.
func wordVerdict(w word) verdict {
	if w.opaque {
		return denyRoot
	}
	return textVerdict(w.text)
}

// textArgs are data programs with no option that runs a program, so their
// arguments are always text.
var textArgs = map[string]bool{"echo": true, "printf": true, "grep": true, "egrep": true, "fgrep": true}

// dataVerdict judges a data program at index k. Its here-documents and
// here-strings are text. Its arguments are text only for textArgs and for
// the message of git commit -m. Everything else, including variables set
// before it (GIT_PAGER=…, LESSOPEN=…) and options that run a program
// (man -P, rg --pre, sort --compress-program, git --upload-pack), is judged
// as text.
func (c *simpleCmd) dataVerdict(name string, k int) verdict {
	v := allow
	for _, w := range c.words[:k] {
		v = worse(v, wordVerdict(w))
	}
	if textArgs[name] {
		return v
	}
	args := c.words[k+1:]
	commit := name == "git" && len(args) > 0 && args[0].text == "commit"
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if commit && (t == "-m" || t == "--message") {
			i++ // the message itself
			continue
		}
		if commit && (strings.HasPrefix(t, "-m") || strings.HasPrefix(t, "--message=")) {
			continue
		}
		v = worse(v, wordVerdict(args[i]))
	}
	return v
}

// isSelf reports whether a command word names the installed psudo: by path
// (~/ and $HOME/ expanded) or, for a bare name, through PATH, and only when it
// resolves to the same file.
func isSelf(text, self string) bool {
	if self == "" {
		return false
	}
	candidate := text
	if home, err := os.UserHomeDir(); err == nil {
		for _, prefix := range []string{"~/", "$HOME/", "${HOME}/"} {
			if strings.HasPrefix(candidate, prefix) {
				candidate = filepath.Join(home, candidate[len(prefix):])
			}
		}
	}
	if !strings.Contains(candidate, "/") {
		found, err := exec.LookPath(candidate)
		if err != nil {
			return false
		}
		candidate = found
	}
	return resolved(candidate) == resolved(self)
}

func resolved(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}
