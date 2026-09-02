package main

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestTraceCommandStartErrorPreservesNameTooLongDiagnostic(t *testing.T) {
	command := exec.Command(strings.Repeat(" ", 4096))
	startErr := command.Start()
	if startErr == nil {
		t.Fatal("long executable name unexpectedly started")
	}

	err := fmt.Errorf("failed to resolve trace targets: start command: %w",
		newTraceCommandExecError(command, startErr))
	if got, want := mainErrorText(err), "exec: File name too long"; got != want {
		t.Fatalf("main error = %q, want %q", got, want)
	}
}

func TestTraceCommandStartErrorPreservesNotFoundDiagnostic(t *testing.T) {
	command := exec.Command("strace-go-command-that-does-not-exist")
	startErr := command.Start()
	if startErr == nil {
		t.Fatal("missing executable unexpectedly started")
	}

	err := newTraceCommandExecError(command, startErr)
	if got, want := mainErrorText(err), "exec: No such file or directory"; got != want {
		t.Fatalf("main error = %q, want %q", got, want)
	}
}
