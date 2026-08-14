package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestSyscallEventContextHandlerPolicy(t *testing.T) {
	tests := []struct {
		name       string
		syscall    string
		shouldOut  bool
		wantRun    bool
		wantOutput bool
	}{
		{name: "printed regular syscall", syscall: "getpid", shouldOut: true, wantRun: true, wantOutput: true},
		{name: "hidden fd state syscall", syscall: "openat", shouldOut: false, wantRun: true, wantOutput: false},
		{name: "hidden regular syscall", syscall: "getpid", shouldOut: false, wantRun: false, wantOutput: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := syscallEventContext{
				meta:        meta.Syscall{Name: tt.syscall},
				shouldPrint: tt.shouldOut,
			}

			if got := ev.shouldRunHandler(); got != tt.wantRun {
				t.Fatalf("shouldRunHandler() = %v, want %v", got, tt.wantRun)
			}
			if got := ev.shouldOutput(); got != tt.wantOutput {
				t.Fatalf("shouldOutput() = %v, want %v", got, tt.wantOutput)
			}
		})
	}
}

func TestSyscallEventContextHandleWithUsesMetadataAndHandlerContext(t *testing.T) {
	ctx := &handler.Context{SysName: "getpid"}
	ev := syscallEventContext{
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: ctx,
	}

	var gotName string
	var gotCtx *handler.Context
	res := ev.handleWith(func(name string, handlerCtx *handler.Context) handler.Result {
		gotName = name
		gotCtx = handlerCtx
		return handler.Result{ArgParts: []string{"ok"}}
	})

	if gotName != "getpid" || gotCtx != ctx {
		t.Fatalf("handler input = name:%s ctx:%p, want getpid/%p", gotName, gotCtx, ctx)
	}
	if len(res.ArgParts) != 1 || res.ArgParts[0] != "ok" {
		t.Fatalf("handler result = %+v, want ok arg", res)
	}
	if got := ev.handleWith(nil); len(got.ArgParts) != 0 {
		t.Fatalf("nil handler result = %+v, want empty", got)
	}
}

func TestSyscallEventContextEffectiveMetadataFallsBackToHandlerContext(t *testing.T) {
	ctx := &handler.Context{ScMeta: meta.Syscall{Name: "exit_group"}}
	ev := syscallEventContext{
		view:           syscallEventView{valid: true, ret: -2},
		handlerContext: ctx,
	}

	if got := ev.effectiveSyscallMeta().Name; got != "exit_group" {
		t.Fatalf("effective metadata name = %q, want exit_group", got)
	}

	var gotName string
	ev.handleWith(func(name string, _ *handler.Context) handler.Result {
		gotName = name
		return handler.Result{}
	})
	if gotName != "exit_group" {
		t.Fatalf("handler syscall name = %q, want exit_group", gotName)
	}
	if ev.shouldEmitStatus(successfulFailedOptions{failedOnly: true}) {
		t.Fatal("exit_group should not be treated as failed when metadata comes from handler context")
	}
}

func TestSyscallEventContextEffectiveMetadataFallsBackToHandlerSysName(t *testing.T) {
	ev := syscallEventContext{
		handlerContext: &handler.Context{SysName: "getpid"},
	}

	if got := ev.effectiveSyscallMeta().Name; got != "getpid" {
		t.Fatalf("effective metadata name = %q, want getpid", got)
	}

	var gotName string
	ev.handleWith(func(name string, _ *handler.Context) handler.Result {
		gotName = name
		return handler.Result{}
	})
	if gotName != "getpid" {
		t.Fatalf("handler syscall name = %q, want getpid", gotName)
	}
}

func TestSyscallEventContextRawEnterPolicy(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[5] = true
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, args: [6]uint64{5}},
		meta:     meta.Syscall{Name: "dup", Args: []string{"fd"}},
		statePID: 101,
		filter:   newTraceFilterOptions(opts),
	}

	if !ev.shouldEmitRawEnter(nil) {
		t.Fatal("raw enter policy should use event view for fd filter")
	}
	ev.filter = nil
	if ev.shouldEmitRawEnter(nil) {
		t.Fatal("raw enter policy should reject nil options")
	}

	opts.DebugEvents = true
	opts.TraceFDs = map[int32]bool{}
	ev.filter = newTraceFilterOptions(opts)
	if !ev.shouldEmitRawEnter(nil) {
		t.Fatal("debug raw enter policy should override filters")
	}
}

func TestSyscallEventContextRawEnterPolicyUsesEffectiveMetadata(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[5] = true
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, args: [6]uint64{5}},
		statePID: 101,
		filter:   newTraceFilterOptions(opts),
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "dup", Args: []string{"fd"}},
		},
	}

	if !ev.shouldEmitRawEnter(nil) {
		t.Fatal("raw enter policy should use effective metadata for fd filter")
	}
}

func TestSyscallEventContextSuppressOutputUsesEffectiveMetadata(t *testing.T) {
	ev := syscallEventContext{
		view: syscallEventView{valid: true, args: [6]uint64{0x1002}},
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "arch_prctl"},
		},
	}

	if !ev.shouldSuppressOutput() {
		t.Fatal("arch_prctl ARCH_SET_FS should be suppressed from effective metadata")
	}

	ev.view.args[0] = 0
	if ev.shouldSuppressOutput() {
		t.Fatal("arch_prctl with non-ARCH_SET_FS arg should not be suppressed")
	}
}

func TestSyscallEventContextRecordSummaryUsesEffectiveMetadata(t *testing.T) {
	stats := &SummaryStats{}
	view := syscallEventView{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     syscallIDByName(t, "getpid"),
		duration:  12,
		ret:       -2,
		eventType: bpfEventTypeExit,
	}
	visibleSession := newBareTestTraceSessionWithOptions(cli.ParseArgs([]string{"-e", "trace=getpid", "/bin/true"}), traceSessionDeps{
		Decoder: event.NewDecoder(),
		FDState: newFDStateStoreFromMaps(nil, nil),
	})
	ev := newSyscallEventContextFromView(visibleSession, view, 101, nil, nil)

	ev.recordSummary(stats)

	entry, ok := stats.stats["getpid"]
	if !ok {
		t.Fatalf("summary entries = %+v, want getpid", stats.stats)
	}
	if entry.calls != 1 || entry.duration != 12 || entry.errors != 1 {
		t.Fatalf("summary entry = %+v, want count=1 time=12 errors=1", entry)
	}

	hiddenSession := newBareTestTraceSessionWithOptions(cli.ParseArgs([]string{"-e", "trace=write", "/bin/true"}), traceSessionDeps{
		Decoder: event.NewDecoder(),
		FDState: newFDStateStoreFromMaps(nil, nil),
	})
	hidden := newSyscallEventContextFromView(hiddenSession, view, 101, nil, nil)
	hidden.recordSummary(stats)
	if stats.stats["getpid"].calls != 1 {
		t.Fatalf("hidden event changed summary entry = %+v", stats.stats["getpid"])
	}
}
