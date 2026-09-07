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
		{name: "trace-fds-negative", args: []string{"--trace-fds=-1", "/bin/true"}, want: "-1"},
		{name: "trace-fd-overflow", args: []string{"--trace-fd=2147483648", "/bin/true"}, want: "2147483648"},
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

func TestParseDescriptorSetRepeatedNegation(t *testing.T) {
	opts := ParseArgs([]string{"-eread=!!!0,1", "/bin/true"})

	if opts.TraceReadFD(0) {
		t.Fatal("repeated negation unexpectedly enabled fd 0")
	}
	if !opts.TraceReadFD(2) {
		t.Fatal("repeated negation disabled fd 2")
	}
}

func TestParseTraceFDDescriptorSets(t *testing.T) {
	all := ParseArgs([]string{"--trace-fds=all", "/bin/true"})
	if !all.TraceFDsConfigured || all.TraceFDsNegated || !all.TraceFDs[TraceAllFDs] {
		t.Fatalf("trace-fds=all = configured:%v negated:%v set:%#v", all.TraceFDsConfigured, all.TraceFDsNegated, all.TraceFDs)
	}

	none := ParseArgs([]string{"--trace-fd=none", "/bin/true"})
	if !none.TraceFDsConfigured || none.TraceFDsNegated || len(none.TraceFDs) != 0 {
		t.Fatalf("trace-fd=none = configured:%v negated:%v set:%#v", none.TraceFDsConfigured, none.TraceFDsNegated, none.TraceFDs)
	}

	alias := ParseArgs([]string{"-e", "fds=!0,,2", "/bin/true"})
	if !alias.TraceFDsConfigured || !alias.TraceFDsNegated || !alias.TraceFDs[0] || !alias.TraceFDs[2] {
		t.Fatalf("fds alias = configured:%v negated:%v set:%#v", alias.TraceFDsConfigured, alias.TraceFDsNegated, alias.TraceFDs)
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
