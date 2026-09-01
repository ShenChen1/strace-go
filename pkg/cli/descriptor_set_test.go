package cli

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

type invalidDescriptorTestCase struct {
	name string
	args []string
	want string
}

func invalidDescriptorTestCases() []invalidDescriptorTestCase {
	return []invalidDescriptorTestCase{
		{name: "empty", args: []string{"-eread=", "/bin/true"}, want: ""},
		{name: "separators", args: []string{"-e", "write=!,,", "/bin/true"}, want: "!,,"},
		{name: "negative", args: []string{"--read=1,-42", "/bin/true"}, want: "-42"},
		{name: "overflow", args: []string{"--write=4294967296", "/bin/true"}, want: "4294967296"},
		{name: "text", args: []string{"-eread=not_fd,1", "/bin/true"}, want: "not_fd"},
		{name: "mixed-all", args: []string{"--write=1,all", "/bin/true"}, want: "all"},
		{name: "mixed-none", args: []string{"-e", "read=1,!none", "/bin/true"}, want: "!none"},
		{name: "embedded-negation", args: []string{"--write=1,!", "/bin/true"}, want: "!"},
		{name: "trailing-space", args: []string{"--read=1 ", "/bin/true"}, want: "1 "},
	}
}

func TestParseDescriptorSetCompatibleForms(t *testing.T) {
	opts := ParseArgs([]string{"-eread=, +1,,2147483647,", "-ewrite=!0,,2", "/bin/true"})

	if !opts.TraceReadFD(1) || !opts.TraceReadFD(2147483647) || opts.TraceReadFD(2) {
		t.Fatalf("read descriptor set = %#v, want {1, 2147483647}", opts.TraceReadFDs)
	}
	if opts.TraceWriteFD(0) || opts.TraceWriteFD(2) || !opts.TraceWriteFD(1) {
		t.Fatalf("negated write descriptor set = %#v, want !{0, 2}", opts.TraceWriteFDs)
	}
}

func TestParseInvalidDescriptorRejected(t *testing.T) {
	caseName := os.Getenv("STRACE_GO_INVALID_DESCRIPTOR_CASE")
	if caseName != "" {
		for _, test := range invalidDescriptorTestCases() {
			if test.name == caseName {
				ParseArgs(test.args)
				return
			}
		}
		t.Fatalf("unknown invalid descriptor test case %q", caseName)
	}

	for _, test := range invalidDescriptorTestCases() {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestParseInvalidDescriptorRejected$")
			cmd.Env = append(os.Environ(), "STRACE_GO_INVALID_DESCRIPTOR_CASE="+test.name)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("ParseArgs(%q) exit = %v, want status 1; stderr=%q", test.args, err, stderr.String())
			}
			want := os.Args[0] + ": invalid descriptor '" + test.want + "'\n"
			if stderr.String() != want {
				t.Fatalf("stderr = %q, want %q", stderr.String(), want)
			}
		})
	}
}
