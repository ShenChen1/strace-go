package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseKillOnExit(t *testing.T) {
	opts := ParseArgs([]string{"--kill-on-exit", "/bin/true"})
	if !opts.KillOnExit {
		t.Fatal("--kill-on-exit was not enabled")
	}
}

func TestParseKillOnExitRejectsAttach(t *testing.T) {
	if os.Getenv("STRACE_GO_INVALID_KILL_ON_EXIT") != "" {
		ParseArgs([]string{"--kill-on-exit", "-p", "123"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestParseKillOnExitRejectsAttach")
	cmd.Env = append(os.Environ(), "STRACE_GO_INVALID_KILL_ON_EXIT=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("kill-on-exit attach conflict exit = %v, want status 1; stderr=%q", err, stderr.String())
	}
	if want := "--kill-on-exit and -p/--attach are mutually exclusive options"; !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}
