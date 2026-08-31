package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseInstructionPointerOptions(t *testing.T) {
	for _, option := range []string{"-i", "--instruction-pointer"} {
		t.Run(option, func(t *testing.T) {
			opts := ParseArgs([]string{option, "/bin/true"})
			if !opts.InstructionPointer {
				t.Fatalf("ParseArgs(%q) InstructionPointer = false", option)
			}
		})
	}
}

func TestInstructionPointerRejectsSummaryOnly(t *testing.T) {
	if os.Getenv("STRACE_GO_INSTRUCTION_POINTER_SUMMARY") != "" {
		ParseArgs([]string{"--instruction-pointer", "--summary-only", "/bin/true"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestInstructionPointerRejectsSummaryOnly")
	cmd.Env = append(os.Environ(), "STRACE_GO_INSTRUCTION_POINTER_SUMMARY=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("summary conflict exit = %v, want status 1; stderr=%q", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-i/--instruction-pointer has no effect with -c/--summary-only") {
		t.Fatalf("stderr = %q, want summary conflict", stderr.String())
	}
}
