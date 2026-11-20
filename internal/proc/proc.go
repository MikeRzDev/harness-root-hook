// Package proc answers two questions about processes: which processes are the
// ancestors of this one, and whether a process is still alive. psudo uses them
// to tie a session's secrets to the harness process that started it: nothing
// the caller puts in the environment can make another process an ancestor.
package proc

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Proc is one process: its id and the name it runs under.
type Proc struct {
	PID  int
	Name string
}

// maxDepth bounds the walk to the root of the process tree.
const maxDepth = 64

// psPath lists every process on macOS, which has no /proc.
const psPath = "/bin/ps"

// lookup returns the parent and name of a process.
type lookup func(pid int) (ppid int, name string, ok bool)

// Ancestors returns the ancestors of this process, nearest first: its parent,
// then the parent's parent, and so on. Process 1 is left out. The list is
// empty when the process table cannot be read.
func Ancestors() []Proc {
	switch runtime.GOOS {
	case "linux":
		return walk(os.Getppid(), procfs)
	case "darwin":
		out, err := exec.Command(psPath, "-axo", "pid=,ppid=,comm=").Output()
		if err != nil {
			return nil
		}
		return walk(os.Getppid(), table(out))
	}
	return nil
}

// walk follows parents from start until process 1 or an unknown process.
func walk(start int, find lookup) []Proc {
	var chain []Proc
	seen := map[int]bool{}
	for pid := start; pid > 1 && !seen[pid] && len(chain) < maxDepth; {
		ppid, name, ok := find(pid)
		if !ok {
			break
		}
		seen[pid] = true
		chain = append(chain, Proc{PID: pid, Name: clean(name)})
		pid = ppid
	}
	return chain
}

// clean reduces a command to its program name: "/usr/bin/zsh" and "-zsh" (a
// login shell) are both "zsh".
func clean(name string) string {
	return strings.TrimPrefix(filepath.Base(strings.TrimSpace(name)), "-")
}

// table parses `ps -axo pid=,ppid=,comm=` output into a lookup.
func table(out []byte) lookup {
	type row struct {
		ppid int
		name string
	}
	rows := map[int]row{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		// The command may contain spaces; it is everything after the two numbers.
		rest := strings.TrimSpace(string(line))
		rest = strings.TrimSpace(strings.TrimPrefix(rest, fields[0]))
		rest = strings.TrimSpace(strings.TrimPrefix(rest, fields[1]))
		rows[pid] = row{ppid, rest}
	}
	return func(pid int) (int, string, bool) {
		r, ok := rows[pid]
		return r.ppid, r.name, ok
	}
}

// procfs reads one process from Linux's /proc.
func procfs(pid int) (int, string, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, "", false
	}
	return parseStat(string(data))
}

// parseStat reads "pid (name) state ppid …". The name may itself contain
// spaces and parentheses, so it ends at the last ")".
func parseStat(stat string) (int, string, bool) {
	open, end := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 0 || end < open {
		return 0, "", false
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 2 {
		return 0, "", false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, "", false
	}
	return ppid, stat[open+1 : end], true
}

// Alive reports whether a process with this id exists.
func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
