package cli

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

func TestTimestampOptionDiagnosticsMatchUpstream(t *testing.T) {
	caseID := os.Getenv("STRACE_GO_TIMESTAMP_DIAGNOSTIC")
	cases := timestampDiagnosticCases(os.Args[0])
	if caseID != "" {
		for _, test := range cases {
			if test.name == caseID {
				ParseArgs(test.args)
				return
			}
		}
		t.Fatalf("unknown timestamp diagnostic case %q", caseID)
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestTimestampOptionDiagnosticsMatchUpstream$")
			command.Env = append(os.Environ(), "STRACE_GO_TIMESTAMP_DIAGNOSTIC="+test.name)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			err := command.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("ParseArgs(%v) exit = %v, want status 1", test.args, err)
			}
			if got := stderr.String(); got != test.stderr {
				t.Fatalf("stderr = %q, want %q", got, test.stderr)
			}
		})
	}
}

type timestampDiagnosticCase struct {
	name   string
	args   []string
	stderr string
}

func timestampDiagnosticCases(invocation string) []timestampDiagnosticCase {
	help := func(message string) string {
		return invocation + ": " + message + "\nTry '" + invocation + " -h' for more information.\n"
	}
	plain := func(message string) string { return invocation + ": " + message + "\n" }
	conflict := "-t and --absolute-timestamps cannot be provided simultaneously"
	return []timestampDiagnosticCase{
		{name: "absolute", args: []string{"--absolute-timestamps=ss"}, stderr: help("invalid --absolute-timestamps argument: 'ss'")},
		{name: "alias-format", args: []string{"--timestamps=format:s"}, stderr: help("invalid --timestamps argument: 'format:s'")},
		{name: "alias-mixed", args: []string{"--timestamps=s,non"}, stderr: help("invalid --timestamps argument: 's,non'")},
		{name: "alias-precision", args: []string{"--timestamps=precision:none"}, stderr: help("invalid --timestamps argument: 'precision:none'")},
		{name: "relative", args: []string{"--relative-timestamps=n"}, stderr: help("invalid --relative-timestamps argument: 'n'")},
		{name: "syscall", args: []string{"--syscall-times=ss"}, stderr: help("invalid --syscall-times argument: 'ss'")},
		{name: "short-first", args: []string{"-t", "--timestamps", "-p", "1"}, stderr: plain(conflict)},
		{name: "long-first", args: []string{"--absolute-timestamps", "-ttt", "-p", "1"}, stderr: plain(conflict)},
	}
}
