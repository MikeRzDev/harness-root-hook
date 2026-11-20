package secrets

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// minLine is the shortest line of a file secret that is redacted on its own.
const minLine = 12

type pattern struct {
	text  []byte
	label []byte
}

// Patterns returns what to redact for one secret value (docs/secrets.md §7.4).
func Patterns(name string, value []byte, file bool) [][]byte {
	var forms [][]byte
	add := func(v []byte) {
		if len(v) == 0 {
			return
		}
		forms = append(forms, v,
			[]byte(base64.RawStdEncoding.EncodeToString(v)),
			[]byte(base64.RawURLEncoding.EncodeToString(v)),
			[]byte(url.QueryEscape(string(v))),
			[]byte(url.PathEscape(string(v))))
	}
	add(value)
	if file {
		for _, line := range strings.Split(string(value), "\n") {
			if l := strings.TrimSpace(line); len(l) >= minLine {
				add([]byte(l))
			}
		}
	}
	return forms
}

// Redactor replaces secret values in a stream. It holds back only a tail of
// output that could be the start of a match, so ordinary output flows.
type Redactor struct {
	mu       sync.Mutex
	w        io.Writer
	patterns []pattern
	buf      []byte
}

// NewRedactor writes to w with every pattern in byName replaced by
// [REDACTED:<name>].
func NewRedactor(w io.Writer, byName map[string][][]byte) *Redactor {
	r := &Redactor{w: w}
	seen := map[string]bool{}
	for name, list := range byName {
		for _, p := range list {
			if len(p) == 0 || seen[string(p)] {
				continue
			}
			seen[string(p)] = true
			r.patterns = append(r.patterns, pattern{p, []byte("[REDACTED:" + name + "]")})
		}
	}
	// Longest first, so a value wins over a shorter value it contains.
	sort.Slice(r.patterns, func(i, j int) bool { return len(r.patterns[i].text) > len(r.patterns[j].text) })
	return r
}

func (r *Redactor) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if err := r.drain(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes everything held back. Call it after the stream ends.
func (r *Redactor) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.drain(true)
}

func (r *Redactor) drain(final bool) error {
	var out bytes.Buffer
	for {
		at, which := -1, -1
		for i, p := range r.patterns {
			if k := bytes.Index(r.buf, p.text); k >= 0 && (at < 0 || k < at) {
				at, which = k, i
			}
		}
		if at < 0 {
			break
		}
		out.Write(r.buf[:at])
		out.Write(r.patterns[which].label)
		r.buf = r.buf[at+len(r.patterns[which].text):]
	}
	keep := 0
	if !final {
		keep = r.partial()
	}
	out.Write(r.buf[:len(r.buf)-keep])
	r.buf = append(r.buf[:0], r.buf[len(r.buf)-keep:]...)
	if out.Len() == 0 {
		return nil
	}
	_, err := r.w.Write(out.Bytes())
	return err
}

// partial is the length of the longest tail of buf that is a proper prefix
// of some pattern.
func (r *Redactor) partial() int {
	best := 0
	for _, p := range r.patterns {
		start := len(r.buf) - (len(p.text) - 1)
		if start < 0 {
			start = 0
		}
		for i := start; i < len(r.buf); i++ {
			if len(r.buf)-i <= best {
				break
			}
			if r.buf[i] == p.text[0] && bytes.HasPrefix(p.text, r.buf[i:]) {
				best = len(r.buf) - i
				break
			}
		}
	}
	return best
}
