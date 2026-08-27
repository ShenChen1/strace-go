package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseArchitectureConflictsRejected(t *testing.T) {
	caseID := os.Getenv("STRACE_GO_PARSE_CONFLICT")
	if caseID != "" {
		argsByCase := map[string][]string{
			"interruptible": {"--interruptible=waiting", "/bin/true"},
			"overhead":      {"--summary-syscall-overhead=1us", "/bin/true"},
			"seccomp":       {"--seccomp-bpf", "/bin/true"},
			"inject":        {"--inject=read:error=EIO", "/bin/true"},
			"fault":         {"-e", "fault=read", "/bin/true"},
		}
		ParseArgs(argsByCase[caseID])
		return
	}

	for _, test := range architectureConflictCases() {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestParseArchitectureConflictsRejected")
			cmd.Env = append(os.Environ(), "STRACE_GO_PARSE_CONFLICT="+test.name)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("ParseArgs(%s) exit = %v, want status 1; stderr=%q", test.name, err, stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr = %q, want conflict reason %q", stderr.String(), test.want)
			}
		})
	}
}

func architectureConflictCases() []struct{ name, want string } {
	return []struct{ name, want string }{
		{name: "interruptible", want: "ptrace stop signal blocking"},
		{name: "overhead", want: "no ptrace syscall-stop overhead"},
		{name: "seccomp", want: "filtering already occurs in eBPF"},
		{name: "inject", want: "cannot modify tracee state"},
		{name: "fault", want: "cannot modify tracee state"},
	}
}
