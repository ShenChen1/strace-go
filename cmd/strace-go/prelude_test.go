package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"strace-go/pkg/cli"
)

const missingTraceTargetHelperEnv = "STRACE_GO_MISSING_TRACE_TARGET_HELPER"

func TestHandlePreludeReportsMissingTraceTarget(t *testing.T) {
	if os.Getenv(missingTraceTargetHelperEnv) != "" {
		handled, err := handlePrelude(cli.ParseArgs(nil))
		if !handled {
			fmt.Fprintln(os.Stderr, "prelude did not handle missing target")
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestHandlePreludeReportsMissingTraceTarget$")
	command.Args[0] = "strace"
	command.Env = append(os.Environ(), missingTraceTargetHelperEnv+"=1")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 1 {
		t.Fatalf("missing target exit = %v, want status 1", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("missing target stdout = %q, want empty", stdout.String())
	}
	want := "must have PROG [ARGS] or -p PID\nTry 'strace -h' for more information.\n"
	if stderr.String() != want {
		t.Fatalf("missing target stderr = %q, want %q", stderr.String(), want)
	}
}
