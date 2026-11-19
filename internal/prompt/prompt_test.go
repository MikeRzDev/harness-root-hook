package prompt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const evil = `rm -rf "/tmp/x" ; echo '$(id)' <b>bold</b> & "quote" \" end tell`

func env(goos, display, wayland, available string) Env {
	return Env{GOOS: goos,
		Getenv: func(k string) string {
			return map[string]string{"DISPLAY": display, "WAYLAND_DISPLAY": wayland}[k]
		},
		Find: func(name string) string {
			if name == available {
				return "/usr/bin/" + name
			}
			return ""
		}}
}

func TestDialogSelection(t *testing.T) {
	for _, tc := range []struct{ goos, display, wayland, tool, want string }{
		{"linux", ":0", "", "zenity", "/usr/bin/zenity"},
		{"linux", "", "wayland-0", "kdialog", "/usr/bin/kdialog"},
		{"linux", ":0", "", "ssh-askpass", "/usr/bin/ssh-askpass"},
		{"darwin", "", "", "", "/usr/bin/osascript"},
	} {
		name, _, err := env(tc.goos, tc.display, tc.wayland, tc.tool).Command(Request{Title: "t", Command: "c"})
		if err != nil || name != tc.want {
			t.Errorf("%+v: got %s %v", tc, name, err)
		}
	}
	for _, e := range []Env{env("linux", "", "", "zenity"), env("linux", "", "wayland-0", "ssh-askpass"),
		env("linux", ":0", "", ""), env("windows", "", "", "")} {
		if _, _, err := e.Command(Request{}); !errors.Is(err, ErrNoProvider) {
			t.Errorf("%+v: %v", e.GOOS, err)
		}
	}
}

// Model-controlled text must be passed as data and rendered verbatim.
func TestCommandTextIsDataNotCode(t *testing.T) {
	req := Request{Title: "sudo password (Claude Code)", Host: "web-1", Command: evil, Timeout: 30 * time.Second}
	_, args, _ := env("darwin", "", "", "").Command(req)
	if args[1] != macScript || args[2] != req.Title || args[3] != Message("web-1", evil) || args[4] != "30" {
		t.Fatalf("osascript argv %q", args)
	}
	_, args, _ = env("linux", ":0", "", "zenity").Command(req)
	text := args[3]
	if strings.Contains(text, "<b>") || !strings.Contains(text, "&lt;b&gt;bold&lt;/b&gt;") || !strings.Contains(text, "&amp;") {
		t.Fatalf("zenity text not escaped: %q", text)
	}
	_, args, _ = env("linux", ":0", "", "kdialog").Command(req)
	if !strings.HasPrefix(args[3], "<qt><pre>") || strings.Contains(args[3], "<b>") {
		t.Fatalf("kdialog text not escaped: %q", args[3])
	}
	if !strings.Contains(Message("web-1", evil), "Host: web-1") || !strings.Contains(Message("", "x"), "this computer") {
		t.Fatal("message lacks host label")
	}
}

func TestAskOutcomes(t *testing.T) {
	for _, tc := range []struct {
		out  string
		code int
		err  error
		want error
		pw   string
	}{
		{"s3cret\n", 0, nil, nil, "s3cret"},
		{"", 1, nil, ErrCancelled, ""},
		{"", 5, nil, ErrCancelled, ""}, // zenity timeout
		{"\n", 0, nil, ErrCancelled, ""},
		{"a\nb\n", 0, nil, ErrCancelled, ""},
		{"", -1, errors.New("not found"), ErrNoProvider, ""},
	} {
		e := env("darwin", "", "", "")
		e.Run = func(context.Context, string, []string) ([]byte, int, error) { return []byte(tc.out), tc.code, tc.err }
		pw, err := e.Ask(context.Background(), Request{Title: "t", Command: "c"})
		if !errors.Is(err, tc.want) || string(pw) != tc.pw {
			t.Errorf("%+v: got %q %v", tc, pw, err)
		}
	}
}

func TestAskHardTimeoutIsCancel(t *testing.T) {
	e := env("darwin", "", "", "")
	e.Run = func(ctx context.Context, _ string, _ []string) ([]byte, int, error) {
		<-ctx.Done()
		return nil, 1, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := e.Ask(ctx, Request{Timeout: time.Second}); !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
}
