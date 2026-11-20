package proc

import (
	"os"
	"reflect"
	"testing"
)

func TestAncestorsOfThisProcess(t *testing.T) {
	chain := Ancestors()
	if len(chain) == 0 || chain[0].PID != os.Getppid() || chain[0].Name == "" {
		t.Fatalf("ancestors %+v, parent %d", chain, os.Getppid())
	}
	for _, p := range chain {
		if p.PID <= 1 || !Alive(p.PID) {
			t.Errorf("ancestor %+v is not a live process", p)
		}
	}
}

func TestWalkFollowsParentsAndStops(t *testing.T) {
	ps := []byte("    1     0 /sbin/launchd\n" +
		" 1242     1 /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal\n" +
		"68721  1242 -zsh\n" +
		"12573 68721 claude\n" +
		" 1257 12573 /bin/zsh\n" +
		"  900   900 loop\n" +
		"garbage line\n")
	got := walk(1257, table(ps))
	want := []Proc{{1257, "zsh"}, {12573, "claude"}, {68721, "zsh"}, {1242, "Terminal"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// An unknown process ends the walk; a process that is its own parent
	// does not loop.
	if got := walk(4242, table(ps)); len(got) != 0 {
		t.Fatalf("unknown process: %+v", got)
	}
	if got := walk(900, table(ps)); len(got) != 1 {
		t.Fatalf("self-parent: %+v", got)
	}
}

func TestParseStat(t *testing.T) {
	ppid, name, ok := parseStat("4321 (tmux: server (1)) S 77 4321 4321 0 -1 4194560 …")
	if !ok || ppid != 77 || name != "tmux: server (1)" {
		t.Fatalf("%d %q %v", ppid, name, ok)
	}
	for _, bad := range []string{"", "12 no-name S 1", "12 (x)", "12 (x) S notanumber"} {
		if _, _, ok := parseStat(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAlive(t *testing.T) {
	if !Alive(os.Getpid()) || Alive(0) || Alive(-5) {
		t.Fatal("liveness of this process, 0 or a negative id is wrong")
	}
}
