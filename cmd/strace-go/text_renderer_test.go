package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestTextRendererPrintsBasicSyscallLine(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 101},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	if got := output.String(); got != "getpid() = 101\n" {
		t.Fatalf("syscall output = %q", got)
	}
}

func TestTextRendererPrintsSyscallNumberOnDecodedLine(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{AlignCol: 12, PrintSyscallNumber: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState()})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, sysID: 50, ret: 0},
		meta:           meta.Syscall{Name: "listen"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{ArgParts: []string{"0", "0"}})

	if got := output.String(); got != "[  50] listen(0, 0) = 0\n" {
		t.Fatalf("numbered syscall output = %q", got)
	}
}

func TestFormatSyscallArgumentsPrintsNamesAndFallsBackSafely(t *testing.T) {
	tests := []struct {
		name     string
		argNames []string
		parts    []string
		show     bool
		want     string
	}{
		{name: "disabled", argNames: []string{"fd", "op"}, parts: []string{"-1", "LOCK_SH"}, want: "-1, LOCK_SH"},
		{name: "enabled", argNames: []string{"fd", "op"}, parts: []string{"-1", "LOCK_SH"}, show: true, want: "fd=-1, op=LOCK_SH"},
		{name: "missing metadata", argNames: []string{"fd"}, parts: []string{"-1", "LOCK_SH"}, show: true, want: "fd=-1, LOCK_SH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatSyscallArguments(tt.argNames, tt.parts, tt.show); got != tt.want {
				t.Fatalf("formatSyscallArguments() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTextRendererPrintsArgumentNamesOnDecodedLine(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{AlignCol: 40, PrintArgNames: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState()})
	renderer.PrintSyscallEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, ret: -9},
		meta: meta.Syscall{Name: "flock", Args: []string{"fd", "op"}},
	}, handler.Result{ArgParts: []string{"-1", "LOCK_SH"}})

	if got := output.String(); !strings.Contains(got, "flock(fd=-1, op=LOCK_SH)") {
		t.Fatalf("argument-name output = %q", got)
	}
}

func TestTextRendererAlwaysShowsPIDWithoutFollowForks(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{AlignCol: 15, AlwaysShowPID: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState()})
	renderer.PrintSyscallEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 321, ret: -9},
		meta: meta.Syscall{Name: "fchdir", Args: []string{"fd"}},
	}, handler.Result{ArgParts: []string{"-1"}})
	output.WriteString(renderer.ExitStatusLine(321, 0))

	got := output.String()
	for _, want := range []string{"321   fchdir(-1)", "321   +++ exited with 0 +++"} {
		if !strings.Contains(got, want) {
			t.Fatalf("always-show-pid output missing %q in %q", want, got)
		}
	}
}

func TestTextRendererFastPathAlwaysShowsPID(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{AlwaysShowPID: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState()})
	renderer.PrintSyscallEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 321, ret: 321},
		meta: meta.Syscall{Name: "getpid"},
	}, handler.Result{})

	if got := output.String(); !strings.HasPrefix(got, "321   getpid()") {
		t.Fatalf("fast always-show-pid output = %q", got)
	}
}

func TestTextRendererUsesConfiguredSyscallTimePrecision(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{AlignCol: 20, PrintSyscallTime: true, SyscallTimePrecision: "ms"}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState()})
	renderer.PrintSyscallEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, ret: 0, duration: 1_234_567_890},
		meta: meta.Syscall{Name: "getpid"},
	}, handler.Result{})

	if got := output.String(); !strings.Contains(got, "<1.234>") {
		t.Fatalf("millisecond syscall time output = %q", got)
	}
}

func TestTextRendererFastPathPrintsSyscallNumber(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{PrintSyscallNumber: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState()})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, sysID: 39, ret: 101},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	if got := output.String(); got != "[  39] getpid() = 101\n" {
		t.Fatalf("fast numbered syscall output = %q", got)
	}
}

func TestTextRendererFastPathPreservesReturnAlignment(t *testing.T) {
	var output bytes.Buffer
	const alignCol = 40
	opts := &cli.Options{AlignCol: alignCol}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState()})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 101},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	want := "getpid()" + strings.Repeat(" ", alignCol-len("getpid()")) + "= 101\n"
	if got := output.String(); got != want {
		t.Fatalf("aligned syscall output = %q, want %q", got, want)
	}
}

func TestTextRendererPrintsSyscallFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
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
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

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
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintUnfinishedEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101},
		meta: meta.Syscall{Name: "nanosleep"},
	}, handler.Result{ArgParts: []string{"{tv_sec=1}"}})

	if got := output.String(); got != "101   nanosleep({tv_sec=1} <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q", got)
	}
}

func TestTextRendererFastPathDoesNotAlignUnfinishedLine(t *testing.T) {
	var output bytes.Buffer
	const alignCol = 40
	opts := &cli.Options{AlignCol: alignCol}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState()})

	renderer.PrintUnfinishedEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101},
		meta: meta.Syscall{Name: "getpid"},
	}, handler.Result{})

	if got := output.String(); got != "getpid( <unfinished ...>\n" {
		t.Fatalf("unfinished output = %q, want no trailing alignment spaces", got)
	}
}

func TestTextRendererPrintsUnfinishedFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
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
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

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
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintExecResumeFromView(syscallEventView{valid: true, tid: 101, duration: 1_234_000}, `execve("/bin/true")`)

	got := output.String()
	if !strings.Contains(got, `101   execve("/bin/true")`) || !strings.Contains(got, "= 0 <0.001234>") {
		t.Fatalf("exec resume output = %q", got)
	}
}

func TestTextRendererPrintsExecMessagesFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
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
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
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
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
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
	renderer := newTextRenderer(TextRendererDeps{Out: &bytes.Buffer{}, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	got := renderer.ExitStatusLineFromView(syscallEventView{valid: true, tid: 101, args: [6]uint64{7}})

	if got != "101   +++ exited with 7 +++\n" {
		t.Fatalf("exit status line = %q", got)
	}
}

func TestTextRendererPrintsExitSyscallFromEventView(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{FollowForks: true}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})
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
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: state, TimeFormatter: newTimeFormatter(0)})

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

func TestTextRendererFastPathPreservesSuspendedNanosleep(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{}
	state := newTraceState()
	state.rememberSuspendedSyscall(101, "nanosleep")
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: state})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 0},
		meta:           meta.Syscall{Name: "nanosleep"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	if got := output.String(); !strings.Contains(got, "<... nanosleep resumed> <unfinished ...>) = 0") {
		t.Fatalf("suspended nanosleep output = %q", got)
	}
}

func TestTextRendererFastPathHasNoSteadyStateAllocations(t *testing.T) {
	if raceBuild {
		t.Skip("allocation counts include race instrumentation")
	}
	opts := &cli.Options{}
	renderer := newTextRenderer(TextRendererDeps{Out: io.Discard, Policy: newTraceOutputPolicy(opts), State: newTraceState()})
	ev := syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 101},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}
	renderer.PrintSyscallEvent(ev, handler.Result{})

	allocs := testing.AllocsPerRun(100, func() {
		renderer.PrintSyscallEvent(ev, handler.Result{})
	})
	if allocs != 0 {
		t.Fatalf("fast text renderer allocations = %.1f, want zero", allocs)
	}
}

func TestTextRendererAppendsHexDumpWithoutSyntheticSignal(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{}
	renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: -516},
		meta:           meta.Syscall{Name: "nanosleep"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{ArgParts: []string{"0x1"}, HexDumpStr: "HEX\n"})

	got := output.String()
	if !strings.Contains(got, "HEX\n") || strings.Contains(got, "--- SIGALRM") {
		t.Fatalf("extra text output = %q", got)
	}
}

func TestTextRendererDoesNotSynthesizeClockNanosleepSignals(t *testing.T) {
	for _, ret := range []int64{-516, -514} {
		var output bytes.Buffer
		opts := &cli.Options{}
		renderer := newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts), State: newTraceState(), TimeFormatter: newTimeFormatter(0)})

		renderer.PrintSyscallEvent(syscallEventContext{
			view:           syscallEventView{valid: true, tid: 101, ret: ret},
			meta:           meta.Syscall{Name: "clock_nanosleep"},
			handlerContext: &handler.Context{Opts: opts},
		}, handler.Result{ArgParts: []string{"CLOCK_REALTIME", "0", "0x1", "0x2"}})

		if got := output.String(); strings.Contains(got, "--- SIGALRM") {
			t.Fatalf("clock_nanosleep ret %d output = %q, want no fabricated signal", ret, got)
		}
	}
}
