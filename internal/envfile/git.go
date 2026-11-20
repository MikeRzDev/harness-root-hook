package envfile

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// gitTimeout bounds each question to git.
const gitTimeout = 5 * time.Second

// ExecGit asks the git program. Path is the absolute path of git, and Env its
// whole environment: psudo gives it a fixed one, so GIT_DIR, GIT_WORK_TREE or
// a config file chosen by the caller cannot change the answers.
type ExecGit struct {
	Path string
	Env  []string
}

func (g ExecGit) run(dir string, args ...string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	// The repository is the project's, so its config is too. These settings
	// keep git from starting a program the repository names while it answers.
	fixed := []string{"-C", dir, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"}
	cmd := exec.CommandContext(ctx, g.Path, append(fixed, args...)...)
	cmd.Env = g.Env
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if exit, ok := err.(*exec.ExitError); ok {
		return out.String(), exit.ExitCode()
	}
	if err != nil {
		return "", -1
	}
	return out.String(), 0
}

// Root is the top folder of the work tree that contains dir.
func (g ExecGit) Root(dir string) (string, bool) {
	out, code := g.run(dir, "rev-parse", "--show-toplevel")
	root := strings.TrimRight(out, "\r\n")
	return root, code == 0 && root != ""
}

// Ignored reports whether git ignores path. check-ignore exits 0 only for a
// path that an ignore rule matches and that git does not track.
func (g ExecGit) Ignored(root, path string) bool {
	_, code := g.run(root, "check-ignore", "-q", "--", path)
	return code == 0
}
