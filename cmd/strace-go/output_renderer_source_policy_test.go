package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/handler"
)

func TestOutputSubcomponentsUseNarrowRendererPorts(t *testing.T) {
	root := repositoryRoot(t)
	files := []string{
		"cmd/strace-go/exit_syscall_output.go",
		"cmd/strace-go/syscall_text_output.go",
		"cmd/strace-go/exec_syscall_output.go",
		"cmd/strace-go/suspended_syscall_output.go",
	}
	for _, relative := range files {
		source, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		if strings.Contains(string(source), "*TextRenderer") {
			t.Fatalf("%s still depends on concrete TextRenderer", relative)
		}
	}
	textSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/text_renderer.go"))
	for _, required := range []string{
		"type exitSyscallRenderer interface",
		"type syscallTextRenderer interface",
		"type execSyscallRenderer interface",
		"type unfinishedSyscallRenderer interface",
	} {
		if !strings.Contains(textSource, required) {
			t.Fatalf("text renderer port %q is missing", required)
		}
	}
}

type fakeExitSyscallRenderer struct {
	exitCalls   int
	statusCalls int
}

func (r *fakeExitSyscallRenderer) PrintExitSyscallEvent(syscallEventContext, handler.Result) {
	r.exitCalls++
}

func (r *fakeExitSyscallRenderer) ExitStatusLineFromView(syscallEventView) string {
	r.statusCalls++
	return "status\n"
}

type fakeSyscallTextRenderer struct {
	eventCalls      int
	unfinishedCalls int
}

func (r *fakeSyscallTextRenderer) PrintSyscallEvent(syscallEventContext, handler.Result) {
	r.eventCalls++
}

func (r *fakeSyscallTextRenderer) PrintUnfinishedEvent(syscallEventContext, handler.Result) {
	r.unfinishedCalls++
}

type fakeExecSyscallRenderer struct {
	resumeCalls       int
	pidChangedCalls   int
	supersededCalls   int
	suspendedCalls    int
	threadExecveCalls int
	eventCalls        int
}

func (r *fakeExecSyscallRenderer) PrintSyscallEvent(syscallEventContext, handler.Result) {
	r.eventCalls++
}

func (r *fakeExecSyscallRenderer) PrintExecResumeFromView(syscallEventView, string) {
	r.resumeCalls++
}

func (r *fakeExecSyscallRenderer) PrintExecPidChangedFromView(syscallEventView, string) {
	r.pidChangedCalls++
}

func (r *fakeExecSyscallRenderer) PrintExecSupersededUnfinishedFromView(syscallEventView, string) {
	r.supersededCalls++
}

func (r *fakeExecSyscallRenderer) PrintSupersededSuspendedResumeFromView(syscallEventView, string) {
	r.suspendedCalls++
}

func (r *fakeExecSyscallRenderer) PrintThreadExecveSupersededFromView(syscallEventView, string) {
	r.threadExecveCalls++
}

type fakeUnfinishedSyscallRenderer struct {
	calls int
}

func (r *fakeUnfinishedSyscallRenderer) PrintUnfinishedEvent(syscallEventContext, handler.Result) {
	r.calls++
}

func TestOutputSubcomponentsAcceptInjectedRendererPorts(t *testing.T) {
	exitRenderer := &fakeExitSyscallRenderer{}
	textRenderer := &fakeSyscallTextRenderer{}
	execRenderer := &fakeExecSyscallRenderer{}
	unfinishedRenderer := &fakeUnfinishedSyscallRenderer{}

	if exitRenderer == nil || textRenderer == nil || execRenderer == nil || unfinishedRenderer == nil {
		t.Fatal("fake renderer ports unexpectedly nil")
	}
	_ = newExitSyscallOutput(ExitSyscallOutputDeps{Renderer: exitRenderer})
	_ = newSyscallTextOutput(SyscallTextOutputDeps{Renderer: textRenderer})
	_ = newExecSyscallOutput(ExecSyscallOutputDeps{Renderer: execRenderer})
	_ = newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{Renderer: unfinishedRenderer})
}
