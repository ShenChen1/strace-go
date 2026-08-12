package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestSyscallEventContextBuildsPayloadHandlerContext(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"})
	session := newBareTestTraceSession(traceSessionDeps{
		TargetPID: 101,
		Opts:      opts,
		Decoder:   event.NewDecoder(),
		FDState: newFDStateStoreFromMaps(map[string]string{
			"101:cwd": "/tmp",
		}, nil),
		State: newTraceState(),
	})
	path := []byte("input.txt\x00")
	pathPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: uint32(len(path)),
		data:    path,
	})
	args := [6]uint64{rawAtFdcwd, 0x1000, 0}
	session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, "openat", bpfEventTypeEnter, args, 0, pathPayload))
	exitUpdate := session.traceState().handleEnvelope(testTLVSyscallEnvelope(t, "openat", bpfEventTypeExit, args, 3, nil))
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

	if ev.syscallName() != "openat" || !ev.shouldOutput() {
		t.Fatalf("event context behavior = name:%s output:%v, want openat/true", ev.syscallName(), ev.shouldOutput())
	}
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !ok {
		t.Fatalf("handler context missing path payload section")
	}
	if section.UserPtr != 0x1000 || string(section.Data) != string(path) {
		t.Fatalf("payload section = ptr:%#x data:%q", section.UserPtr, string(section.Data))
	}
	if ev.handlerContext.TargetPid != 101 {
		t.Fatalf("handler context target mismatch: %+v", ev.handlerContext)
	}
	if len(ev.handlerContext.PayloadSections) != 1 {
		t.Fatalf("handler context payload sections = %d, want 1", len(ev.handlerContext.PayloadSections))
	}
	ev.updateFDState(session.fdStateStore())
	if got := session.fdStateStore().paths["101:3"]; got != "input.txt" {
		t.Fatalf("fd path = %q, want input.txt from path snapshot", got)
	}
}

func TestSyscallEventContextWithDepsBuildsHandlerContext(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=getpid", "/bin/true"})
	decoder := event.NewDecoder()
	fdState := newFDStateStoreFromMaps(map[string]string{"101:cwd": "/tmp"}, nil)
	runtime := handler.NewRuntime()
	catalog := meta.NewCatalog("raw")
	view := syscallEventView{
		valid: true,
		pid:   101,
		tid:   102,
		sysID: syscallIDByName(t, "getpid"),
		ret:   102,
	}

	ev := newSyscallEventContextFromViewWithDeps(
		syscallEventContextDeps{
			decoder: decoder,
			opts:    opts,
			catalog: catalog,
			fdState: fdState,
			fdPath:  fdState,
			runtime: runtime,
		},
		view,
		101,
		nil,
		nil,
	)

	if ev.handlerContext.Decoder != decoder || ev.handlerContext.Opts != opts {
		t.Fatalf("handler context deps = decoder:%p opts:%p, want %p/%p", ev.handlerContext.Decoder, ev.handlerContext.Opts, decoder, opts)
	}
	if ev.handlerContext.Meta != catalog {
		t.Fatalf("handler context catalog = %p, want %p", ev.handlerContext.Meta, catalog)
	}
	if ev.handlerContext.Runtime != runtime {
		t.Fatal("handler context did not receive the session-scoped runtime")
	}
	if got, ok := ev.handlerContext.FDStateView.Cwd(101); !ok || got != "/tmp" {
		t.Fatalf("handler fd state cwd = %q, %v; want session fd state path", got, ok)
	}
}

func TestSyscallEventContextIgnoresLegacyPathStringBuffer(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"})
	session := newBareTestTraceSession(traceSessionDeps{
		TargetPID: 101,
		Opts:      opts,
		Decoder:   event.NewDecoder(),
		FDState:   newFDStateStoreFromMaps(nil, nil),
	})
	view := syscallEventView{
		valid:         true,
		pid:           101,
		tid:           101,
		sysID:         syscallIDByName(t, "openat"),
		args:          [6]uint64{rawAtFdcwd, 0x1000, 0},
		ptr:           0x1000,
		probeRetEnter: 0,
		ret:           -2,
	}

	ev := newSyscallEventContextFromView(session, view, 101, nil, nil)
	if _, ok := ev.handlerContext.Section(1, handler.PayloadKindString); ok {
		t.Fatalf("handler context unexpectedly exposed legacy path string section")
	}
	ev.updateFDState(session.fdStateStore())
	if got := session.fdStateStore().paths["101:3"]; got != "" {
		t.Fatalf("fd path = %q, want no update from legacy string buffer", got)
	}
}

func TestDecodePathArgumentsUsesArgumentPointerFallback(t *testing.T) {
	session := newBareTestTraceSession(traceSessionDeps{Decoder: event.NewDecoder()})
	sc := meta.Syscall{Name: "custom_path_syscall", Args: []string{"path"}}
	view := syscallEventView{valid: true, tid: 101, args: [6]uint64{0x2000}}

	got := decodePathArguments(newSyscallEventContextDeps(session), view, sc, nil)

	if len(got) != 1 || got[0].Text != "0x2000" || got[0].DirFD != handler.AtFdcwd {
		t.Fatalf("path arguments = %+v, want pointer with AT_FDCWD", got)
	}
}

func TestDecodePathArgumentsUsesMatchingPayloadSection(t *testing.T) {
	session := newBareTestTraceSession(traceSessionDeps{Decoder: event.NewDecoder()})
	sc := meta.Syscall{Name: "custom_path_syscall", Args: []string{"path"}}
	view := syscallEventView{valid: true, tid: 101, args: [6]uint64{0x2000}}
	sections := []handler.PayloadSection{{
		Kind:      handler.PayloadKindString,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  0,
		UserPtr:   0x2000,
		ProbeRet:  0,
		Data:      []byte("view.txt\x00"),
	}}

	got := decodePathArguments(newSyscallEventContextDeps(session), view, sc, sections)

	if len(got) != 1 || got[0].Text != `"view.txt"` {
		t.Fatalf("path arguments = %+v, want payload matched by arg index", got)
	}
}

func TestSyscallEventContextHandlerContextUsesEventView(t *testing.T) {
	session := newBareTestTraceSession(traceSessionDeps{
		TargetPID: 101,
		Opts:      cli.ParseArgs([]string{"/bin/true"}),
		Decoder:   event.NewDecoder(),
		FDState:   newFDStateStoreFromMaps(nil, nil),
	})
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 101, tid: 102, sysID: 39, args: [6]uint64{7}, ret: -2, probeRetEnter: -1, probeRetExit: 0},
		statePID: 101,
		meta:     syscallMeta(39),
	}

	ctx := ev.newHandlerContext(newSyscallEventContextDeps(session))

	if ctx.Pid != 101 || ctx.Tid != 102 || ctx.SysId != 39 {
		t.Fatalf("handler context identity = pid:%d tid:%d sys:%d, want 101/102/39", ctx.Pid, ctx.Tid, ctx.SysId)
	}
	if ctx.Args[0] != 7 || ctx.Ret != -2 || ctx.ProbeRetEnter != -1 {
		t.Fatalf("handler context syscall fields = args:%v ret:%d probe:%d", ctx.Args, ctx.Ret, ctx.ProbeRetEnter)
	}
}

func TestSyscallEventContextHandlerContextUsesEffectiveMetadata(t *testing.T) {
	session := newBareTestTraceSession(traceSessionDeps{
		TargetPID: 101,
		Opts:      cli.ParseArgs([]string{"/bin/true"}),
		Decoder:   event.NewDecoder(),
		FDState:   newFDStateStoreFromMaps(nil, nil),
	})
	scMeta := meta.Syscall{Name: "pipe"}
	fdData := fdArrayJSONData(21, 22)
	ev := syscallEventContext{
		view: syscallEventView{
			valid:        true,
			pid:          101,
			tid:          101,
			eventType:    bpfEventTypeExit,
			ret:          0,
			probeRetExit: 0,
		},
		statePID: 101,
		meta:     scMeta,
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindStruct,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  0,
			UserLen:   uint32(len(fdData)),
			CopiedLen: uint32(len(fdData)),
			ProbeRet:  0,
			Data:      fdData,
		}},
	}
	ev.handlerContext = &handler.Context{ScMeta: scMeta}

	ctx := ev.newHandlerContext(newSyscallEventContextDeps(session))

	if ctx.SysName != "pipe" || ctx.ScMeta.Name != "pipe" {
		t.Fatalf("handler metadata = sys:%q sc:%q, want pipe/pipe", ctx.SysName, ctx.ScMeta.Name)
	}
	if len(ctx.PayloadSections) != 1 {
		t.Fatalf("handler payload sections = %d, want effective pipe payload", len(ctx.PayloadSections))
	}
}

func TestSyscallEnterEventContextUsesEventViewAndMetadata(t *testing.T) {
	view := syscallEventView{
		valid: true,
		pid:   101,
		tid:   102,
		sysID: 39,
		args:  [6]uint64{7},
		ret:   -2,
	}

	ev := newSyscallEnterEventContextWithCatalog(view, 201, nil, meta.NewCatalog("abbrev"))

	if ev.syscallName() != "getpid" {
		t.Fatalf("enter context syscall name = %q, want getpid", ev.syscallName())
	}
	if ev.handlerContextForFormatting() != nil {
		t.Fatalf("enter context should not build handler context: %+v", ev.handlerContextForFormatting())
	}
	if sections := ev.outputPayloadSections(); sections != nil {
		t.Fatalf("enter context payload sections = %+v, want nil", sections)
	}
	gotView := ev.eventView()
	if gotView.pid != 101 || gotView.tid != 102 || gotView.sysID != 39 || gotView.args[0] != 7 || gotView.ret != -2 {
		t.Fatalf("enter context view = %+v, want view-derived syscall fields", gotView)
	}
}

func TestSyscallEnterEventContextUsesSessionCatalog(t *testing.T) {
	view := syscallEventView{valid: true, sysID: 39}
	catalog := meta.NewCatalog("raw")

	ev := newSyscallEnterEventContextWithCatalog(view, 201, nil, catalog)

	if ev.catalog != catalog {
		t.Fatalf("enter context catalog = %p, want session catalog %p", ev.catalog, catalog)
	}
}

func TestSyscallEnterEventContextCachesPayloadSections(t *testing.T) {
	pathPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: uint32(len([]byte("enter-path\x00"))),
		data:    []byte("enter-path\x00"),
	})
	update := newTraceState().handleEnvelope(testTLVSyscallEnvelope(
		t,
		"openat",
		bpfEventTypeEnter,
		[6]uint64{rawAtFdcwd, 0x1000, 0},
		0,
		pathPayload,
	))

	ev := newSyscallEnterEventContextWithCatalog(
		update.syscallView,
		201,
		update.payloadSections,
		meta.NewCatalog("abbrev"),
	)

	sections := ev.outputPayloadSections()
	if len(sections) != 1 {
		t.Fatalf("enter context payload sections = %d, want 1 cached section", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindString || section.ArgIndex != 1 || string(section.Data) != "enter-path\x00" {
		t.Fatalf("enter context section = %+v, want cached TLV path section", section)
	}
}

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
	}

	if !ev.shouldEmitRawEnter(opts, nil) {
		t.Fatal("raw enter policy should use event view for fd filter")
	}
	if ev.shouldEmitRawEnter(nil, nil) {
		t.Fatal("raw enter policy should reject nil options")
	}

	opts.DebugEvents = true
	opts.TraceFDs = map[int32]bool{}
	if !ev.shouldEmitRawEnter(opts, nil) {
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
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "dup", Args: []string{"fd"}},
		},
	}

	if !ev.shouldEmitRawEnter(opts, nil) {
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
	visibleSession := newBareTestTraceSession(traceSessionDeps{
		Opts:    cli.ParseArgs([]string{"-e", "trace=getpid", "/bin/true"}),
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

	hiddenSession := newBareTestTraceSession(traceSessionDeps{
		Opts:    cli.ParseArgs([]string{"-e", "trace=write", "/bin/true"}),
		Decoder: event.NewDecoder(),
		FDState: newFDStateStoreFromMaps(nil, nil),
	})
	hidden := newSyscallEventContextFromView(hiddenSession, view, 101, nil, nil)
	hidden.recordSummary(stats)
	if stats.stats["getpid"].calls != 1 {
		t.Fatalf("hidden event changed summary entry = %+v", stats.stats["getpid"])
	}
}
