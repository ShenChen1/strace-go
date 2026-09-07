package main

import (
	"strings"
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
	detached.detachedByExecPolicy = true
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

func TestExecSyscallOutputPrintsDetachedNonLeaderIdentityChange(t *testing.T) {
	output, _, out, discarded := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	syscall := meta.Syscall{Name: "execve"}
	result := handler.Result{ArgParts: []string{`"../status-detached-threads"`, `["../status-detached-threads", "0"]`, `NULL`}}
	detached := execOutputEvent(syscall, 200, 201, 0)
	detached.detached = true
	detached.detachedByExecPolicy = true

	if !output.HandleEvent(detached, result) {
		t.Fatal("detached non-leader exec should be handled")
	}
	want := "201   execve(\"../status-detached-threads\", [\"../status-detached-threads\", \"0\"], NULL <pid changed to 200 ...>\n" +
		"200   +++ superseded by execve in pid 201 +++\n"
	if got := out.String(); got != want {
		t.Fatalf("detached non-leader output = %q, want %q", got, want)
	}
	if len(*discarded) != 1 || (*discarded)[0] != 200 {
		t.Fatalf("discarded exit statuses = %v, want [200]", *discarded)
	}
}

func TestExecSyscallOutputDoesNotTreatDetachedStatusAsDetachPolicy(t *testing.T) {
	output, _, out, _ := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	syscall := meta.Syscall{Name: "execve"}
	result := handler.Result{ArgParts: []string{`"/bin/true"`, `["true"]`, `NULL`}}

	if !output.HandleEvent(execOutputEvent(syscall, 200, 201, -514), result) {
		t.Fatal("non-leader exec restart should be handled")
	}
	success := execOutputEvent(syscall, 200, 201, 0)
	success.detached = true
	if !output.HandleEvent(success, result) {
		t.Fatal("status-detached non-leader exec should be handled")
	}

	if got := out.String(); !strings.Contains(got, "<... execve resumed>) = 0") {
		t.Fatalf("status-detached exec used detach output path: %q", got)
	}
}

func TestExecSyscallOutputStatusDetachedOmitsResumeLine(t *testing.T) {
	output, _, out, _ := newExecSyscallOutputForTest(&cli.Options{FollowForks: true})
	syscall := meta.Syscall{Name: "execve"}
	result := handler.Result{ArgParts: []string{`"/bin/true"`, `["true"]`, `NULL`}}

	if !output.HandleEvent(execOutputEvent(syscall, 200, 201, -514), result) {
		t.Fatal("non-leader exec restart should be handled")
	}
	success := execOutputEvent(syscall, 200, 201, 0)
	success.detached = true
	success.detachedByStatus = true
	if !output.HandleEvent(success, result) {
		t.Fatal("status-detached non-leader exec should be handled")
	}

	got := out.String()
	if !strings.Contains(got, "+++ superseded by execve in pid 201 +++") {
		t.Fatalf("status-detached output = %q, want superseded marker", got)
	}
	if strings.Contains(got, "<... execve resumed>) = 0") {
		t.Fatalf("status-detached output = %q, want no exec resume", got)
	}
}
