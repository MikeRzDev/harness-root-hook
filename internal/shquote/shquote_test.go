package shquote

import "testing"

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":         "''",
		"abc-1.2":  "abc-1.2",
		"a b":      "'a b'",
		"it's":     `'it'"'"'s'`,
		"$(x) `y`": "'$(x) `y`'",
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Join([]string{"sh", "-c", "echo hi"}); got != "sh -c 'echo hi'" {
		t.Errorf("Join = %q", got)
	}
}

// Text shown in a dialog must not contain anything the user cannot see.
func TestVisible(t *testing.T) {
	for in, want := range map[string]string{
		"plain text, with ünïcödé and 日本語": "plain text, with ünïcödé and 日本語",
		"two\nlines\tand a tab":            "two\nlines\tand a tab",
		"rtl\u202eoverride":                `rtl\u{202E}override`,
		"zero\u200bwidth":                  `zero\u{200B}width`,
		"no-break\u00a0space":              `no-break\u{00A0}space`,
		"esc\x1b[2K":                       `esc\u{001B}[2K`,
		"cr\rback":                         `cr\u{000D}back`,
		"bad\xffutf8":                      `bad\x{FF}utf8`,
		"line\u2028separator":              `line\u{2028}separator`,
	} {
		if got := Visible(in); got != want {
			t.Errorf("Visible(%q) = %q, want %q", in, got, want)
		}
	}
	if got := VisibleLine("/work\n\nCommand:\tx"); got != `/work\n\nCommand:\tx` {
		t.Errorf("VisibleLine = %q", got)
	}
	if got := VisibleLine("/Users/me/My Project"); got != "/Users/me/My Project" {
		t.Errorf("VisibleLine changed a plain path: %q", got)
	}
}
