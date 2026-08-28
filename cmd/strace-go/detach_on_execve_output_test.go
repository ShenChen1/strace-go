package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestExecSyscallOutputPrintsDetachedLine(t *testing.T) {
	output, state, out, _ := newExecSyscallOutputForTest(&cli.Options{})
	syscall := meta.Syscall{Name: "execve"}
	result := handler.Result{ArgParts: []string{`"../sleep"`, `["../sleep", "0"]`, `NULL`}}

	if !output.HandleEvent(execOutputEvent(syscall, 200, 200, -514), result) {
		t.Fatal("exec restart should be handled")
	}
	detached := execOutputEvent(syscall, 200, 200, 0)
	detached.detached = true
	if !output.HandleEvent(detached, result) {
		t.Fatal("detached exec success should be handled")
	}

	want := "execve(\"../sleep\", [\"../sleep\", \"0\"], NULL <detached ...>\n"
	if got := out.String(); got != want {
		t.Fatalf("detached exec output = %q, want %q", got, want)
	}
	if _, ok := state.pendingExecArgsFor(200); ok {
		t.Fatal("detached exec did not consume pending arguments")
	}
}
