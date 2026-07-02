package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestTextRendererPrintsBasicSyscallLine(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintSyscall(&bpfEvent{Tid: 101, Ret: 101}, meta.Syscall{Name: "getpid"}, handler.Result{}, &handler.Context{Opts: opts})

	if got := output.String(); got != "getpid() = 101\n" {
		t.Fatalf("syscall output = %q", got)
	}
}

func TestTextRendererConsumesSuspendedSyscall(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{}
	state := newTraceState()
	state.rememberSuspendedSyscall(101, "nanosleep")
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: state, TimeFormatter: newTimeFormatter(0)})

	renderer.PrintSyscall(&bpfEvent{Tid: 101, Ret: 0}, meta.Syscall{Name: "nanosleep"}, handler.Result{ArgParts: []string{"0x1"}}, &handler.Context{Opts: opts})

	got := output.String()
	if !strings.Contains(got, "<... nanosleep resumed> <unfinished ...>) = 0") {
		t.Fatalf("suspended syscall output = %q", got)
	}
	if state.consumeSuspendedSyscall(101) {
		t.Fatal("suspended syscall marker was not consumed")
	}
}

func TestTextRendererAppendsHexDumpAndSignalLine(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintSyscall(
		&bpfEvent{Tid: 101, Ret: -516},
		meta.Syscall{Name: "nanosleep"},
		handler.Result{ArgParts: []string{"0x1"}, HexDumpStr: "HEX\n"},
		&handler.Context{Opts: opts},
	)

	got := output.String()
	if !strings.Contains(got, "HEX\n") || !strings.Contains(got, "--- SIGALRM") {
		t.Fatalf("extra text output = %q", got)
	}
}
