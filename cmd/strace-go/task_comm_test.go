package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestEscapeTaskCommMatchesUpstreamPIDDecoration(t *testing.T) {
	tests := map[string]string{
		"plain":         "plain",
		"foo\x1b[2Jbar": `foo\33[2Jbar`,
		"foo<bar>":      `foo\x3cbar\x3e`,
	}
	for input, want := range tests {
		if got := escapeTaskComm(input); got != want {
			t.Fatalf("escapeTaskComm(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTaskCommStoreTracksNULTerminatedNames(t *testing.T) {
	store := newTaskCommStore()
	store.Observe(101, "0123456789abcde\x00ignored")
	if got, ok := store.Lookup(101); !ok || got != "0123456789abcde" {
		t.Fatalf("Lookup(101) = %q, %v", got, ok)
	}
	store.Forget(101)
	if _, ok := store.Lookup(101); ok {
		t.Fatal("forgotten comm remained visible")
	}
}

func TestTextRendererDecoratesPIDPrefixArgumentsAndReturn(t *testing.T) {
	var output bytes.Buffer
	renderer := newTextRenderer(TextRendererDeps{
		Out:    &output,
		Policy: newTraceOutputPolicy(&cli.Options{DecodePIDsComm: true, FollowForks: true, AlignCol: 18}),
		State:  newTraceState(),
	})
	renderer.taskComms.Observe(202, "parent")
	renderer.PrintSyscallEvent(syscallEventContext{
		view: syscallEventView{valid: true, pid: 101, tid: 101, ret: 202, comm: "child"},
		meta: meta.Syscall{Name: "getppid"},
	}, handler.Result{})
	renderer.PrintSyscallEvent(syscallEventContext{
		view: syscallEventView{valid: true, pid: 101, tid: 101, args: [6]uint64{101, 101, 18}, comm: "child"},
		meta: meta.Syscall{Name: "tgkill", ArgTypes: []string{"pid_t", "pid_t", "int"}},
	}, handler.Result{ArgParts: []string{"101", "101", "SIGCONT"}})

	got := output.String()
	for _, want := range []string{
		"101<child> getppid() = 202<parent>",
		"101<child> tgkill(101<child>, 101<child>, SIGCONT)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("decoded PID output missing %q:\n%s", want, got)
		}
	}
}

func TestTextRendererUsesLifecycleObservedCommForExitStatus(t *testing.T) {
	renderer := newTextRenderer(TextRendererDeps{
		Policy: newTraceOutputPolicy(&cli.Options{DecodePIDsComm: true, FollowForks: true}),
	})
	renderer.ObserveTaskComm(303, "exe")
	if got := renderer.ExitStatusLine(303, 0); got != "303<exe> +++ exited with 0 +++\n" {
		t.Fatalf("exit status = %q", got)
	}
}
