package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseDetachOnExecve(t *testing.T) {
	for _, args := range [][]string{
		{"-b", "execve", "/bin/true"},
		{"--detach-on=execve", "/bin/true"},
	} {
		opts := ParseArgs(args)
		if !opts.DetachOnExecve {
			t.Fatalf("ParseArgs(%q) DetachOnExecve = false, want true", args)
		}
	}
}

func TestParseInvalidDetachOnExecveRejected(t *testing.T) {
	if os.Getenv("STRACE_GO_INVALID_DETACH_ON") != "" {
		ParseArgs([]string{"--detach-on=execveat", "/bin/true"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestParseInvalidDetachOnExecveRejected")
	cmd.Env = append(os.Environ(), "STRACE_GO_INVALID_DETACH_ON=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("invalid detach-on exit = %v, want status 1; stderr=%q", err, stderr.String())
	}
	if want := "Syscall 'execveat' for -b isn't supported"; !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}
