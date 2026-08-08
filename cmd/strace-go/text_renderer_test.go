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

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 101},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	if got := output.String(); got != "getpid() = 101\n" {
		t.Fatalf("syscall output = %q", got)
	}
}

func TestTextRendererPrintsSyscallFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	ev := syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 202},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}

	renderer.PrintSyscallEvent(ev, handler.Result{})

	if got := output.String(); got != "101   getpid() = 202\n" {
		t.Fatalf("syscall output = %q", got)
	}
}

func TestTextRendererPrintsSyscallFromHandlerMetadata(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintSyscallEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, ret: 101},
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "getpid"},
			Opts:   opts,
		},
	}, handler.Result{})

	if got := output.String(); got != "getpid() = 101\n" {
		t.Fatalf("syscall output = %q", got)
	}
}

func TestTextRendererPrintsUnfinishedLine(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintUnfinishedEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101},
		meta: meta.Syscall{Name: "nanosleep"},
	}, handler.Result{ArgParts: []string{"{tv_sec=1}"}})

	if got := output.String(); got != "101   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q", got)
	}
}

func TestTextRendererPrintsUnfinishedFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	ev := syscallEventContext{
		view: syscallEventView{valid: true, tid: 101},
		meta: meta.Syscall{Name: "nanosleep"},
	}

	renderer.PrintUnfinishedEvent(ev, handler.Result{ArgParts: []string{"{tv_sec=1}", "0x0"}})

	if got := output.String(); got != "101   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q", got)
	}
}

func TestTextRendererPrintsUnfinishedWithEventTime(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true, PrintRelativeTime: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintUnfinishedEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, enterTime: 1_234_567_000},
		meta: meta.Syscall{Name: "read"},
	}, handler.Result{ArgParts: []string{"3", "\"\"", "4"}})

	if got := output.String(); got != "     0.000000 101   read(3, \"\", 4 <unfinished ...>\n" {
		t.Fatalf("unfinished event-time output = %q", got)
	}
}

func TestTextRendererPrintsExecResumeWithDuration(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true, PrintSyscallTime: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintExecResumeFromView(syscallEventView{valid: true, tid: 101, duration: 1_234_000}, `execve("/bin/true")`)

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
			t.Fatalf("superseded output missing %q in %q", want, got)
		}
	}
}

func TestTextRendererPrintsExitLines(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
	view := syscallEventView{valid: true, tid: 101, args: [6]uint64{7}}

	renderer.PrintExitSyscallEvent(syscallEventContext{
		view: view,
		meta: meta.Syscall{Name: "exit_group"},
	}, handler.Result{ArgParts: []string{"7"}})
	if got := output.String(); got != "101   exit_group(7) = ?\n" {
		t.Fatalf("exit syscall output = %q", got)
	}
	if got := renderer.ExitStatusLineFromView(view); got != "101   +++ exited with 7 +++\n" {
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

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 0},
		meta:           meta.Syscall{Name: "nanosleep"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{ArgParts: []string{"0x1"}})

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

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: -516},
		meta:           meta.Syscall{Name: "nanosleep"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{ArgParts: []string{"0x1"}, HexDumpStr: "HEX\n"})

	got := output.String()
	if !strings.Contains(got, "HEX\n") || !strings.Contains(got, "--- SIGALRM") {
		t.Fatalf("extra text output = %q", got)
	}
}

func TestTextRendererPrintsClockNanosleepSignalLines(t *testing.T) {
	for _, ret := range []int64{-516, -514} {
		var output bytes.Buffer
		opts := &cli.Options{}
		renderer := newTextRenderer(TextRendererDeps{Out: &output, Opts: opts, State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

		renderer.PrintSyscallEvent(syscallEventContext{
			view:           syscallEventView{valid: true, tid: 101, ret: ret},
			meta:           meta.Syscall{Name: "clock_nanosleep"},
			handlerContext: &handler.Context{Opts: opts},
		}, handler.Result{ArgParts: []string{"CLOCK_REALTIME", "0", "0x1", "0x2"}})

		if got := output.String(); !strings.Contains(got, "--- SIGALRM") {
			t.Fatalf("clock_nanosleep ret %d output = %q, want SIGALRM line", ret, got)
		}
	}
}
