package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseSyscallLimit(t *testing.T) {
	opts := ParseArgs([]string{"--syscall-limit=17", "/bin/true"})

	if opts.SyscallLimit != 17 {
		t.Fatalf("SyscallLimit = %d, want 17", opts.SyscallLimit)
	}
}

func TestParseInvalidSyscallLimitRejected(t *testing.T) {
	invalid := os.Getenv("STRACE_GO_INVALID_SYSCALL_LIMIT")
	if invalid != "" {
		ParseArgs([]string{"--syscall-limit", invalid, "/bin/true"})
		return
	}

	for _, value := range []string{"0", "-5", "invalid"} {
		t.Run(value, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestParseInvalidSyscallLimitRejected")
			cmd.Env = append(os.Environ(), "STRACE_GO_INVALID_SYSCALL_LIMIT="+value)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("ParseArgs(%q) exit = %v, want status 1; stderr=%q", value, err, stderr.String())
			}
			want := "invalid --syscall-limit argument: '" + value + "'"
			if !strings.Contains(stderr.String(), want) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), want)
			}
		})
	}
}
