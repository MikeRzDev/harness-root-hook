// Package shquote quotes strings for POSIX shells, matching Python's shlex.quote.
package shquote

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

func safe(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
		strings.ContainsRune("_@%+=:,./-", r)
}

// Quote returns s unchanged when it contains only shell-safe characters,
// otherwise wrapped in single quotes with embedded quotes escaped.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if !safe(r) {
			return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
		}
	}
	return s
}

// Join quotes each argument and joins them with spaces.
func Join(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = Quote(a)
	}
	return strings.Join(quoted, " ")
}

// Visible returns s as it should be shown in a dialog. Characters a reader
// cannot see or that reorder the text around them (control characters,
// bidirectional overrides, zero-width and other non-ASCII spaces, invalid
// UTF-8) are replaced by a \u{…} escape. Newlines and tabs stay as they are.
func Visible(s string) string { return visible(s, false) }

// VisibleLine is Visible for text that must stay on one line, such as a path:
// newlines and tabs are escaped too, so the text cannot start a line of its
// own in the dialog.
func VisibleLine(s string) string { return visible(s, true) }

func visible(s string, oneLine bool) string {
	clean := true
	for _, r := range s {
		if hidden(r, oneLine) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x{%02X}`, s[i])
		case r == '\n' && oneLine:
			b.WriteString(`\n`)
		case r == '\t' && oneLine:
			b.WriteString(`\t`)
		case hidden(r, oneLine):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

func hidden(r rune, oneLine bool) bool {
	if r == '\n' || r == '\t' {
		return oneLine
	}
	// IsPrint is false for control and format characters and for every space
	// except the ASCII one. RuneError is what invalid UTF-8 decodes to.
	return r == utf8.RuneError || !unicode.IsPrint(r)
}
