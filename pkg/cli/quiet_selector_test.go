package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseQuietSelectorRuntimeMessages(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		exit       bool
		unknownPID bool
		threadExec bool
	}{
		{name: "explicit", args: []string{"--quiet=exit,thread-execve", "/bin/true"}, exit: true, threadExec: true},
		{name: "all", args: []string{"--quiet=all", "/bin/true"}, exit: true, unknownPID: true, threadExec: true},
		{name: "none", args: []string{"--quiet=none", "/bin/true"}},
		{name: "negated", args: []string{"--quiet=!thread-execve", "/bin/true"}, exit: true, unknownPID: true},
		{name: "exit alias", args: []string{"-e", "quiet=exits", "/bin/true"}, exit: true},
		{name: "short q", args: []string{"-q", "/bin/true"}, unknownPID: true},
		{name: "short qq", args: []string{"-qq", "/bin/true"}, exit: true, unknownPID: true},
		{name: "short qqq", args: []string{"-qqq", "/bin/true"}, exit: true, unknownPID: true, threadExec: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := ParseArgs(test.args)
			if opts.QuietExit != test.exit || opts.QuietUnknownPid != test.unknownPID ||
				opts.QuietThreadExecve != test.threadExec {
				t.Fatalf("quiet state = exit:%v unknown:%v thread:%v, want %v/%v/%v",
					opts.QuietExit, opts.QuietUnknownPid, opts.QuietThreadExecve,
					test.exit, test.unknownPID, test.threadExec)
			}
		})
	}
}

func TestParseQuietSelectorAliases(t *testing.T) {
	for _, qualifier := range []string{"q=none", "silent=attach,personality"} {
		opts := ParseArgs([]string{"-e", qualifier, "/bin/true"})
		if opts.QuietExit || opts.QuietThreadExecve {
			t.Fatalf("quiet alias %q enabled runtime messages: %+v", qualifier, opts)
		}
	}
}

func TestParseQuietSelectorLongAliases(t *testing.T) {
	for _, option := range []string{"--silent=exits", "--silence=exits"} {
		opts := ParseArgs([]string{option, "/bin/true"})
		if !opts.QuietExit {
			t.Fatalf("quiet alias %q did not suppress exits", option)
		}
	}
}

func TestParseInvalidQuietRejected(t *testing.T) {
	caseName := os.Getenv("STRACE_GO_INVALID_QUIET")
	if caseName != "" {
		args := []string{"--quiet=detach", "/bin/true"}
		if caseName == "mixed" {
			args = []string{"-q", "--quiet=none", "/bin/true"}
		}
		ParseArgs(args)
		return
	}

	tests := []struct {
		name string
		want string
	}{
		{name: "invalid", want: "invalid quiet 'detach'"},
		{name: "mixed", want: "-q and -e quiet/--quiet cannot be provided simultaneously"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestParseInvalidQuietRejected")
			cmd.Env = append(os.Environ(), "STRACE_GO_INVALID_QUIET="+test.name)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("quiet %s exit = %v, want status 1; stderr=%q", test.name, err, stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.want)
			}
		})
	}
}
