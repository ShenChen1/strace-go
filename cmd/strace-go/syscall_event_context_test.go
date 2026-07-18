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
	session := &traceSession{
		targetPid: 101,
		opts:      opts,
		decoder:   event.NewDecoder(),
		fdState: newFDStateStoreFromMaps(map[string]string{
			"101:cwd": "/tmp",
		}, nil),
	}
	path := []byte("input.txt\x00")
	eventRaw := tlvOpenatEvent(t, path)

	ev := newSyscallEventContextFromBPF(session, eventRaw, 101, nil)

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
	if got := session.fdStateStore().PathMap()["101:3"]; got != "input.txt" {
		t.Fatalf("fd path = %q, want input.txt from path snapshot", got)
	}
}

func TestSyscallEventContextIgnoresLegacyPathStringBuffer(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"})
	session := &traceSession{
		targetPid: 101,
		opts:      opts,
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
	}
	path := []byte("legacy.txt\x00")
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         syscallIDByName(t, "openat"),
		Args:          [6]uint64{rawAtFdcwd, 0x1000, 0},
		Ptr:           0x1000,
		DataLen:       uint32(len(path)),
		ProbeRetEnter: 0,
		Ret:           -2,
	}
	copy(eventRaw.StrArg[:], path)

	ev := newSyscallEventContextFromBPF(session, eventRaw, 101, nil)
	if _, ok := ev.handlerContext.Section(1, handler.PayloadKindString); ok {
		t.Fatalf("handler context unexpectedly exposed legacy path string section")
	}
	ev.updateFDState(session.fdStateStore())
	if got := session.fdStateStore().PathMap()["101:3"]; got != "" {
		t.Fatalf("fd path = %q, want no update from legacy string buffer", got)
	}
}

func TestDecodePathTextUsesEventViewPointerFallback(t *testing.T) {
	session := &traceSession{decoder: event.NewDecoder()}
	sc := meta.Syscall{Name: "custom_path_syscall", Args: []string{"path"}}
	view := syscallEventView{valid: true, tid: 101, ptr: 0x2000}

	got := decodePathText(session, view, sc, true, nil)

	if got != "0x2000" {
		t.Fatalf("pathText = %q, want pointer from event view", got)
	}
}

func TestDecodePathTextMatchesPayloadWithEventViewPointer(t *testing.T) {
	session := &traceSession{decoder: event.NewDecoder()}
	sc := meta.Syscall{Name: "custom_path_syscall", Args: []string{"path"}}
	view := syscallEventView{valid: true, tid: 101, ptr: 0x2000}
	sections := []handler.PayloadSection{{
		Kind:      handler.PayloadKindString,
		Direction: handler.PayloadDirectionIn,
		UserPtr:   0x2000,
		ProbeRet:  0,
		Data:      []byte("view.txt\x00"),
	}}

	got := decodePathText(session, view, sc, true, sections)

	if got != `"view.txt"` {
		t.Fatalf("pathText = %q, want payload matched by event view pointer", got)
	}
}

func TestSyscallEventContextHandlerContextUsesEventView(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
	}
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, pid: 101, tid: 102, sysID: 39, args: [6]uint64{7}, ret: -2, probeRetEnter: -1, probeRetExit: 0},
		statePID: 101,
		meta:     syscallMeta(39),
	}

	ctx := ev.newHandlerContext(session)

	if ctx.Pid != 101 || ctx.Tid != 102 || ctx.SysId != 39 {
		t.Fatalf("handler context identity = pid:%d tid:%d sys:%d, want 101/102/39", ctx.Pid, ctx.Tid, ctx.SysId)
	}
	if ctx.Args[0] != 7 || ctx.Ret != -2 || ctx.ProbeRetEnter != -1 {
		t.Fatalf("handler context syscall fields = args:%v ret:%d probe:%d", ctx.Args, ctx.Ret, ctx.ProbeRetEnter)
	}
}

func TestSyscallEventContextHandlerContextUsesEffectiveMetadata(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
	}
	scMeta := meta.Syscall{Name: "pipe"}
	raw := &bpfEvent{
		Pid:          101,
		Tid:          101,
		EventType:    bpfEventTypeExit,
		Ret:          0,
		ProbeRetExit: 0,
		DataLen:      uint32(payloadExitArgOffset + 8),
	}
	ev := syscallEventContextFromRawForTest(raw, scMeta, 101)
	ev.handlerContext = &handler.Context{ScMeta: scMeta}

	ctx := ev.newHandlerContext(session)

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

	ev := newSyscallEnterEventContext(view, 201, nil)

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

func TestSyscallEnterEventContextCachesPayloadSections(t *testing.T) {
	raw := tlvOpenatEvent(t, []byte("enter-path\x00"))
	raw.EventType = bpfEventTypeEnter
	raw.EventFlags |= bpfEventFlagGenericEnter
	raw.Ret = 0
	update := newTraceState().handleEnvelope(newTraceEventEnvelopeFromBPF(raw))

	ev := newSyscallEnterEventContext(update.syscallView, 201, update.payloadSections)

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
	raw := &bpfEvent{
		Pid:      101,
		Tid:      101,
		SysId:    syscallIDByName(t, "getpid"),
		Duration: 12,
		Ret:      -2,
	}
	visibleSession := &traceSession{
		opts:    cli.ParseArgs([]string{"-e", "trace=getpid", "/bin/true"}),
		decoder: event.NewDecoder(),
		fdState: newFDStateStoreFromMaps(nil, nil),
	}
	ev := newSyscallEventContextFromBPF(visibleSession, raw, 101, nil)

	ev.recordSummary(stats)

	entry, ok := stats.stats["getpid"]
	if !ok {
		t.Fatalf("summary entries = %+v, want getpid", stats.stats)
	}
	if entry.calls != 1 || entry.duration != 12 || entry.errors != 1 {
		t.Fatalf("summary entry = %+v, want count=1 time=12 errors=1", entry)
	}

	hiddenSession := &traceSession{
		opts:    cli.ParseArgs([]string{"-e", "trace=write", "/bin/true"}),
		decoder: event.NewDecoder(),
		fdState: newFDStateStoreFromMaps(nil, nil),
	}
	hidden := newSyscallEventContextFromBPF(hiddenSession, raw, 101, nil)
	hidden.recordSummary(stats)
	if stats.stats["getpid"].calls != 1 {
		t.Fatalf("hidden event changed summary entry = %+v", stats.stats["getpid"])
	}
}
