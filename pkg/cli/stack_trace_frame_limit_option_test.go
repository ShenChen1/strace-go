package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseStackTraceFrameLimit(t *testing.T) {
	if got := ParseArgs([]string{"-k", "/bin/true"}).StackFrameLimit; got != DefaultStackTraceFrameLimit {
		t.Fatalf("default frame limit = %d, want %d", got, DefaultStackTraceFrameLimit)
	}
	for _, args := range [][]string{
		{"-k", "--stack-trace-frame-limit=3", "/bin/true"},
		{"--stack-trace", "--stack-trace-frame-limit", "3", "/bin/true"},
	} {
		opts := ParseArgs(args)
		if opts.StackFrameLimit != 3 || !opts.StackFrameLimitSet {
			t.Fatalf("frame limit = %d configured:%v, want 3/true", opts.StackFrameLimit, opts.StackFrameLimitSet)
		}
	}
}

func TestParseInvalidStackTraceFrameLimitRejected(t *testing.T) {
	value := os.Getenv("STRACE_GO_INVALID_STACK_FRAME_LIMIT")
	if value != "" {
		ParseArgs([]string{"-k", "--stack-trace-frame-limit=" + value, "/bin/true"})
		return
	}

	for _, value := range []string{"0", "1073741824"} {
		t.Run(value, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestParseInvalidStackTraceFrameLimitRejected$")
			command.Env = append(os.Environ(), "STRACE_GO_INVALID_STACK_FRAME_LIMIT="+value)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			err := command.Run()
			exitError, ok := err.(*exec.ExitError)
			if !ok || exitError.ExitCode() != 1 {
				t.Fatalf("frame limit %s exit = %v, want status 1", value, err)
			}
			want := "invalid --stack-trace-frame-limit argument: '" + value + "'"
			if !strings.Contains(stderr.String(), want) || !strings.Contains(stderr.String(), "for more information") {
				t.Fatalf("stderr = %q, want %q and help hint", stderr.String(), want)
			}
		})
	}
}

func TestStackTraceFrameLimitWarnsWithoutStackTrace(t *testing.T) {
	if os.Getenv("STRACE_GO_UNUSED_STACK_FRAME_LIMIT") != "" {
		ParseArgs([]string{"--stack-trace-frame-limit=3", "/bin/true"})
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestStackTraceFrameLimitWarnsWithoutStackTrace$")
	command.Env = append(os.Environ(), "STRACE_GO_UNUSED_STACK_FRAME_LIMIT=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("unused frame limit parse = %v, stderr=%q", err, stderr.String())
	}
	want := "--stack-trace-frame-limit has no effect without -k/--stack-trace"
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}
