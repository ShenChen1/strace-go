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
	fdState := newFDStateStoreFromMaps(map[string]string{"101:cwd": "/tmp"}, nil)
	session := newBareTestTraceSessionWithOptions(opts, traceSessionDeps{
		TargetPID: 101,
		Decoder:   event.NewDecoder(),
		FDState:   fdState,
		State:     newTraceState(),
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
	if got, ok := fdState.Path(101, 3); !ok || got != "input.txt" {
		t.Fatalf("fd path = %q, want input.txt from path snapshot", got)
	}
}

func TestMergePendingPayloadSectionsReusesOwnerWithoutExitPayload(t *testing.T) {
	pending := &pendingSyscallSnapshot{
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindString,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			Data:      []byte("path\x00"),
		}},
	}
	wantOwner := &pending.payloadSections[0]

	got := mergePendingPayloadSections(pending, nil)

	if len(got) != 1 || &got[0] != wantOwner {
		t.Fatalf("payload owner changed: got=%p want=%p", &got[0], wantOwner)
	}
	if pending.payloadSections[0].Data[0] != 'p' {
		t.Fatalf("pending payload data changed: %q", pending.payloadSections[0].Data)
	}
}

func TestMergePendingPayloadSectionsUpdatesOwnerInPlace(t *testing.T) {
	pending := &pendingSyscallSnapshot{
		payloadSections: make([]handler.PayloadSection, 1, 3),
	}
	pending.payloadSections[0] = handler.PayloadSection{
		Kind:      handler.PayloadKindString,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  1,
		UserPtr:   0x1000,
		Data:      []byte("old\x00"),
	}
	wantOwner := &pending.payloadSections[0]
	exitPath := handler.PayloadSection{
		Kind:      handler.PayloadKindString,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  1,
		UserPtr:   0x1000,
		Data:      []byte("new\x00"),
	}
	exitFD := handler.PayloadSection{
		Kind:      handler.PayloadKindFDState,
		Direction: handler.PayloadDirectionOut,
		ArgIndex:  0,
		UserPtr:   0,
		Data:      []byte("fd-state"),
	}

	got := mergePendingPayloadSections(pending, []handler.PayloadSection{exitPath, exitFD})

	if len(got) != 2 || &got[0] != wantOwner {
		t.Fatalf("merged payload owner = %p len=%d, want owner=%p len=2", &got[0], len(got), wantOwner)
	}
	if string(got[0].Data) != "new\x00" || got[0].UserPtr != exitPath.UserPtr {
		t.Fatalf("replaced payload = %+v, want exit path", got[0])
	}
	if got[1].Kind != handler.PayloadKindFDState || string(got[1].Data) != "fd-state" {
		t.Fatalf("appended payload = %+v, want fd state", got[1])
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
	policy := newTraceEventPolicy(opts)

	ev := newSyscallEventContextFromViewWithDeps(
		syscallEventContextDeps{
			decoder:     decoder,
			handlerOpts: policy.handlerOptions,
			filter:      policy.filter,
			catalog:     catalog,
			fdState:     fdState,
			fdPath:      fdState,
			runtime:     runtime,
		},
		view,
		101,
		nil,
		nil,
	)

	if ev.handlerContext.Decoder != decoder || ev.handlerContext.Opts != policy.handlerOptions {
		t.Fatalf("handler context deps = decoder:%p opts:%T, want decoder and snapshot", ev.handlerContext.Decoder, ev.handlerContext.Opts)
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
	fdState := newFDStateStoreFromMaps(nil, nil)
	session := newBareTestTraceSessionWithOptions(opts, traceSessionDeps{
		TargetPID: 101,
		Decoder:   event.NewDecoder(),
		FDState:   fdState,
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
	if got, ok := fdState.Path(101, 3); ok && got != "" {
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
	session := newBareTestTraceSessionWithOptions(cli.ParseArgs([]string{"/bin/true"}), traceSessionDeps{
		TargetPID: 101,
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
	session := newBareTestTraceSessionWithOptions(cli.ParseArgs([]string{"/bin/true"}), traceSessionDeps{
		TargetPID: 101,
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

	ev := newSyscallEnterEventContextWithFlagDecoder(view, 201, nil, meta.NewCatalog("abbrev"), nil)

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

	ev := newSyscallEnterEventContextWithFlagDecoder(view, 201, nil, catalog, nil)

	if ev.fdFlags != catalog {
		t.Fatalf("enter context flag decoder = %p, want session catalog %p", ev.fdFlags, catalog)
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

	ev := newSyscallEnterEventContextWithFlagDecoder(
		update.syscallView,
		201,
		update.payloadSections,
		meta.NewCatalog("abbrev"),
		nil,
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
