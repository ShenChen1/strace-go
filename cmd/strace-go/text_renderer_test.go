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

func TestTextRendererPrintsSyscallFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	ev := syscallEventContext{
		raw:            &bpfEvent{Tid: 1, Ret: 1},
		view:           syscallEventView{valid: true, tid: 101, ret: 202},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}

	renderer.PrintSyscallEvent(ev, handler.Result{})

	if got := output.String(); got != "101   getpid() = 202\n" {
		t.Fatalf("syscall output = %q", got)
	}
}

func TestTextRendererPrintsUnfinishedLine(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintUnfinished(&bpfEvent{Tid: 101}, meta.Syscall{Name: "nanosleep"}, handler.Result{ArgParts: []string{"{tv_sec=1}"}})

	if got := output.String(); got != "101   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q", got)
	}
}

func TestTextRendererPrintsUnfinishedFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	ev := syscallEventContext{
		raw:  &bpfEvent{Tid: 1},
		view: syscallEventView{valid: true, tid: 101},
		meta: meta.Syscall{Name: "nanosleep"},
	}

	renderer.PrintUnfinishedEvent(ev, handler.Result{ArgParts: []string{"{tv_sec=1}", "0x0"}})

	if got := output.String(); got != "101   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q", got)
	}
}

func TestTextRendererPrintsExecResumeWithDuration(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true, PrintSyscallTime: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintExecResume(&bpfEvent{Tid: 101, Duration: 1_234_000}, `execve("/bin/true")`)

	got := output.String()
	if !strings.Contains(got, `101   execve("/bin/true")`) || !strings.Contains(got, "= 0 <0.001234>") {
		t.Fatalf("exec resume output = %q", got)
	}
}

func TestTextRendererPrintsExecMessagesFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	view := syscallEventView{valid: true, pid: 200, tid: 201}

	renderer.PrintExecPidChangedFromView(view, `execve("/bin/true")`)
	renderer.PrintExecSupersededUnfinishedFromView(view, `execve("/bin/true")`)
	renderer.PrintSupersededSuspendedResumeFromView(view, "rt_sigsuspend")
	renderer.PrintThreadExecveSupersededFromView(view, "execve")

	got := output.String()
	for _, want := range []string{
		`201   execve("/bin/true" <pid changed to 200 ...>`,
		`201   execve("/bin/true" <unfinished ...>`,
		`200   <... rt_sigsuspend resumed>) = ?`,
		`200   +++ superseded by execve in pid 201 +++`,
		`200   <... execve resumed>) = 0`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("view exec output missing %q in %q", want, got)
		}
	}
}

func TestTextRendererPrintsSupersededExecMessages(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	eventRaw := &bpfEvent{Pid: 200, Tid: 201}

	renderer.PrintExecPidChanged(eventRaw, `execve("/bin/true")`)
	renderer.PrintExecSupersededUnfinished(eventRaw, `execve("/bin/true")`)
	renderer.PrintSupersededSuspendedResume(&bpfEvent{Pid: 200, Tid: 201}, "rt_sigsuspend")
	renderer.PrintThreadExecveSuperseded(eventRaw, "execve")

	got := output.String()
	for _, want := range []string{
		`201   execve("/bin/true" <pid changed to 200 ...>`,
		`201   execve("/bin/true" <unfinished ...>`,
		`200   <... rt_sigsuspend resumed>) = ?`,
		`200   +++ superseded by execve in pid 201 +++`,
		`200   <... execve resumed>) = 0`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("superseded output missing %q in %q", want, got)
		}
	}
}

func TestTextRendererPrintsExitLines(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	eventRaw := &bpfEvent{Tid: 101, Args: [6]uint64{7}}

	renderer.PrintExitSyscall(eventRaw, meta.Syscall{Name: "exit_group"}, handler.Result{ArgParts: []string{"7"}})
	if got := output.String(); got != "101   exit_group(7) = ?\n" {
		t.Fatalf("exit syscall output = %q", got)
	}
	if got := renderer.ExitStatusLine(eventRaw); got != "101   +++ exited with 7 +++\n" {
		t.Fatalf("exit status line = %q", got)
	}
}

func TestTextRendererPrintsExitStatusFromEventView(t *testing.T) {
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &bytes.Buffer{}, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	got := renderer.ExitStatusLineFromView(syscallEventView{valid: true, tid: 101, args: [6]uint64{7}})

	if got != "101   +++ exited with 7 +++\n" {
		t.Fatalf("exit status line = %q", got)
	}
}

func TestTextRendererPrintsExitSyscallFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	ev := syscallEventContext{
		raw:  &bpfEvent{Tid: 1},
		view: syscallEventView{valid: true, tid: 101},
		meta: meta.Syscall{Name: "exit_group"},
	}

	renderer.PrintExitSyscallEvent(ev, handler.Result{ArgParts: []string{"7"}})

	if got := output.String(); got != "101   exit_group(7) = ?\n" {
		t.Fatalf("exit syscall output = %q", got)
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
