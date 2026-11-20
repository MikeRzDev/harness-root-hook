package cache

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
)

// Result is the outcome of an external command.
type Result struct {
	Stdout, Stderr string
	Code           int
}

// ExecFunc runs name with args, feeding stdin when non-nil. It returns an
// error only when the command could not be started.
type ExecFunc func(name string, args []string, stdin []byte) (Result, error)

// Run is the production ExecFunc.
func Run(name string, args []string, stdin []byte) (Result, error) {
	cmd := exec.Command(name, args...)
	// Never the caller's environment as it is: see HelperEnv.
	cmd.Env = HelperEnv(os.Environ())
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errOut.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.Code = exitErr.ExitCode()
		return res, nil
	}
	return res, err
}
