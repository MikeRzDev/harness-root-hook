// Package shquote quotes strings for POSIX shells, matching Python's shlex.quote.
package shquote

import "strings"

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
