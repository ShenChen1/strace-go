package main

import (
	"encoding/binary"
	"io"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestTraceStatePendingFreelistReusesAfterRelease(t *testing.T) {
	sysID := benchmarkSyscallID("getpid")
	enterRaw := benchmarkTraceEventV2Sample(bpfEventTypeEnter, sysID, 1000, 0, 0)
	exitRaw := benchmarkTraceEventV2Sample(bpfEventTypeExit, sysID, 1050, 50, 0)
	enter, ok := decodeTraceEventV2Envelope(enterRaw)
	if !ok {
		t.Fatal("benchmark enter sample was rejected")
	}
	exit, ok := decodeTraceEventV2Envelope(exitRaw)
	if !ok {
		t.Fatal("benchmark exit sample was rejected")
	}
	state := newTraceStateWithDeferredExit(false)
	state.handleEnvelope(enter)
	update := state.handleEnvelope(exit)
	if update.pendingEnter == nil {
		t.Fatal("warm-up pair did not produce a pending enter")
	}
	state.releaseTraceStateUpdate(update)

	allocs := testing.AllocsPerRun(100, func() {
		state.handleEnvelope(enter)
		update := state.handleEnvelope(exit)
		state.releaseTraceStateUpdate(update)
	})
	if allocs != 0 {
		t.Fatalf("steady-state pending pair allocations = %.1f, want zero", allocs)
	}
}

func TestTraceStatePayloadStorageReusesSteadyState(t *testing.T) {
	if raceBuild {
		t.Skip("allocation counts include race instrumentation")
	}
	sysID := benchmarkSyscallID("write")
	enter := traceEventEnvelope{
		valid:      true,
		pid:        1000,
		tid:        1000,
		sysID:      sysID,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  1000,
		payload: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x2000,
			UserLen:   7,
			CopiedLen: 7,
			Data:      []byte("payload"),
		}},
	}
	fragment := enter
	fragment.eventType = bpfEventTypeExit
	fragment.eventFlags = bpfEventFlagExitFragment | bpfEventFlagPayloadTLV
	fragment.payload = []handler.PayloadSection{{
		Kind:      handler.PayloadKindBytes,
		Direction: handler.PayloadDirectionOut,
		ArgIndex:  2,
		UserPtr:   0x3000,
		UserLen:   5,
		CopiedLen: 5,
		Data:      []byte("reply"),
	}}
	exit := fragment
	exit.eventFlags = 0
	exit.payload = nil
	state := newTraceStateWithDeferredExit(false)
	warmTraceStatePayloadPair(state, enter, fragment, exit)

	allocs := testing.AllocsPerRun(100, func() {
		warmTraceStatePayloadPair(state, enter, fragment, exit)
	})
	if allocs != 0 {
		t.Fatalf("steady-state payload enter/fragment allocations = %.1f, want zero", allocs)
	}
}

func TestTraceStateDeferredPayloadStorageReusesSteadyState(t *testing.T) {
	if raceBuild {
		t.Skip("allocation counts include race instrumentation")
	}
	sysID := benchmarkSyscallID("read")
	exit := traceEventEnvelope{
		valid:     true,
		pid:       1000,
		tid:       1000,
		sysID:     sysID,
		enterTime: 1000,
		eventType: bpfEventTypeExit,
		payload: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  1,
			UserPtr:   0x4000,
			UserLen:   5,
			CopiedLen: 5,
			Data:      []byte("reply"),
		}},
	}
	enter := exit
	enter.eventType = bpfEventTypeEnter
	enter.eventFlags = bpfEventFlagGenericEnter
	enter.payload = nil
	state := newTraceStateWithDeferredExit(true)
	warmTraceStateDeferredPayloadPair(state, exit, enter)

	allocs := testing.AllocsPerRun(100, func() {
		warmTraceStateDeferredPayloadPair(state, exit, enter)
	})
	if allocs != 0 {
		t.Fatalf("steady-state deferred payload allocations = %.1f, want zero", allocs)
	}
}

func warmTraceStatePayloadPair(
	state *TraceState,
	enter traceEventEnvelope,
	fragment traceEventEnvelope,
	exit traceEventEnvelope,
) {
	state.releaseTraceStateUpdate(state.handleEnvelope(enter))
	state.releaseTraceStateUpdate(state.handleEnvelope(fragment))
	state.releaseTraceStateUpdate(state.handleEnvelope(exit))
}

func warmTraceStateDeferredPayloadPair(
	state *TraceState,
	exit traceEventEnvelope,
	enter traceEventEnvelope,
) {
	state.releaseTraceStateUpdate(state.handleEnvelope(exit))
	state.releaseTraceStateUpdate(state.handleEnvelope(enter))
}

func BenchmarkTraceEventDecodeState(b *testing.B) {
	sysID := benchmarkSyscallID("getpid")
	enterRaw := benchmarkTraceEventV2Sample(bpfEventTypeEnter, sysID, 1000, 0, 0)
	exitRaw := benchmarkTraceEventV2Sample(bpfEventTypeExit, sysID, 1050, 50, 0)
	state := newTraceStateWithDeferredExit(false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter, ok := decodeTraceEventV2Envelope(enterRaw)
		if !ok {
			b.Fatal("benchmark enter sample was rejected")
		}
		state.handleEnvelope(enter)

		exit, ok := decodeTraceEventV2Envelope(exitRaw)
		if !ok {
			b.Fatal("benchmark exit sample was rejected")
		}
		update := state.handleEnvelope(exit)
		state.releaseTraceStateUpdate(update)
	}
}

func BenchmarkTraceEventDecodeStateWithoutUnfinished(b *testing.B) {
	sysID := benchmarkSyscallID("getpid")
	enterRaw := benchmarkTraceEventV2Sample(bpfEventTypeEnter, sysID, 1000, 0, 0)
	exitRaw := benchmarkTraceEventV2Sample(bpfEventTypeExit, sysID, 1050, 50, 0)
	state := newTraceStateWithDeferredExit(false)
	state.setUnfinishedEnabled(false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter, ok := decodeTraceEventV2Envelope(enterRaw)
		if !ok {
			b.Fatal("benchmark enter sample was rejected")
		}
		state.handleEnvelope(enter)

		exit, ok := decodeTraceEventV2Envelope(exitRaw)
		if !ok {
			b.Fatal("benchmark exit sample was rejected")
		}
		update := state.handleEnvelope(exit)
		state.releaseTraceStateUpdate(update)
	}
}

func BenchmarkTraceStateDeferredPayload(b *testing.B) {
	sysID := benchmarkSyscallID("read")
	exit := traceEventEnvelope{
		valid:     true,
		pid:       1000,
		tid:       1000,
		sysID:     sysID,
		enterTime: 1000,
		eventType: bpfEventTypeExit,
		payload: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  1,
			Data:      []byte("reply"),
		}},
	}
	enter := exit
	enter.eventType = bpfEventTypeEnter
	enter.eventFlags = bpfEventFlagGenericEnter
	enter.payload = nil
	state := newTraceStateWithDeferredExit(true)
	warmTraceStateDeferredPayloadPair(state, exit, enter)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		warmTraceStateDeferredPayloadPair(state, exit, enter)
	}
}

func BenchmarkTraceEventContextHandler(b *testing.B) {
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatHandler}, traceSessionDeps{
		TargetPID: 101,
	})
	deps := newSyscallEventContextDeps(session)
	deps.contextPool = newHandlerContextRecyclerWithPorts(handlerContextSessionPortsFromDeps(deps))
	runner := session.syscallHandlerRunner()
	view := syscallEventView{
		valid:         true,
		pid:           101,
		tid:           101,
		sysID:         benchmarkSyscallID("getpid"),
		eventType:     bpfEventTypeExit,
		ret:           101,
		enterTime:     950,
		duration:      50,
		probeRetEnter: -1,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, nil)
		if _, ok := runner.Handle(ev); !ok {
			b.Fatal("handler benchmark event was not selected")
		}
		ev.releaseHandlerContext()
	}
}

func BenchmarkTraceEventHandlerPipeline(b *testing.B) {
	benchmarkTraceEventPipeline(b, cli.EventFormatHandler)
}

func BenchmarkTraceEventTextPipeline(b *testing.B) {
	benchmarkTraceEventPipeline(b, cli.EventFormatText)
}

func BenchmarkTraceEventJSONPipeline(b *testing.B) {
	benchmarkTraceEventPipeline(b, cli.EventFormatJSON)
}

func BenchmarkTraceEventRouterJSONElidedPlainExit(b *testing.B) {
	output, err := newTraceOutput(TraceOutputDeps{Writer: io.Discard})
	if err != nil {
		b.Fatalf("newTraceOutput() error = %v", err)
	}
	if err := output.EnableBuffer(traceOutputBufferSize); err != nil {
		b.Fatalf("EnableBuffer() error = %v", err)
	}
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatJSON}, traceSessionDeps{
		TargetPID: 101,
		OutWriter: output,
		Output:    output,
	})
	router := session.traceEventRouter()
	if router == nil {
		b.Fatal("trace event router was not composed")
	}
	envelope := traceEventEnvelope{
		valid:     true,
		pid:       101,
		tid:       101,
		sysID:     benchmarkSyscallID("getpid"),
		eventType: bpfEventTypeExit,
		ret:       101,
		enterTime: 950,
		duration:  50,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.Handle(envelope)
	}
}

func benchmarkTraceEventPipeline(b *testing.B, format string) {
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: format}, traceSessionDeps{
		TargetPID: 101,
	})
	deps := newSyscallEventContextDeps(session)
	deps.contextPool = newHandlerContextRecyclerWithPorts(handlerContextSessionPortsFromDeps(deps))
	pipeline := session.syscallExitPipeline()
	if pipeline == nil {
		b.Fatal("pipeline was not composed")
	}
	view := syscallEventView{
		valid:         true,
		pid:           101,
		tid:           101,
		sysID:         benchmarkSyscallID("getpid"),
		eventType:     bpfEventTypeExit,
		ret:           101,
		enterTime:     950,
		duration:      50,
		probeRetEnter: -1,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := newSyscallEventContextFromViewWithDeps(deps, view, 101, nil, nil)
		pipeline.Handle(ev)
	}
}

func TestJSONEventWriterReusesSyscallEventStorage(t *testing.T) {
	if raceBuild {
		t.Skip("allocation counts include race instrumentation")
	}
	sysID := benchmarkSyscallID("getpid")
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})
	event := syscallEventContext{
		view: syscallEventView{
			valid:        true,
			eventVersion: traceEventV2Version,
			pid:          101,
			tid:          101,
			sysID:        sysID,
			eventType:    bpfEventTypeExit,
			ret:          0,
			duration:     50,
			enterTime:    950,
		},
		meta: meta.Syscall{Name: "getpid"},
	}

	writer.WriteRaw(event)
	allocs := testing.AllocsPerRun(100, func() {
		writer.WriteRaw(event)
	})
	if allocs != 0 {
		t.Fatalf("steady-state JSON syscall writer allocations = %.1f, want zero", allocs)
	}
}

func BenchmarkJSONEventWriter(b *testing.B) {
	sysID := benchmarkSyscallID("getpid")
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})
	event := benchmarkJSONWriterEvent(sysID, meta.Syscall{Name: "getpid"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.WriteRaw(event)
	}
}

func BenchmarkJSONDecodedEventWriter(b *testing.B) {
	sysID := benchmarkSyscallID("getpid")
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})
	event := benchmarkJSONWriterEvent(sysID, meta.Syscall{Name: "getpid"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.WriteDecoded(event, handler.Result{})
	}
}

func BenchmarkJSONDecodedPayloadEventWriter(b *testing.B) {
	sysID := benchmarkSyscallID("write")
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})
	event := benchmarkJSONWriterEvent(sysID, meta.Syscall{Name: "write"})
	event.handlerContext = &handler.Context{
		PayloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x2000,
			UserLen:   7,
			CopiedLen: 7,
			Data:      []byte("payload"),
		}},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.WriteDecoded(event, handler.Result{})
	}
}

func benchmarkJSONWriterEvent(sysID uint32, scMeta meta.Syscall) syscallEventContext {
	return syscallEventContext{
		view: syscallEventView{
			valid:        true,
			eventVersion: traceEventV2Version,
			pid:          101,
			tid:          101,
			sysID:        sysID,
			eventType:    bpfEventTypeExit,
			ret:          0,
			duration:     50,
			enterTime:    950,
		},
		meta: scMeta,
	}
}

func benchmarkSyscallID(name string) uint32 {
	for id, syscall := range meta.SyscallTable {
		if syscall.Name == name {
			return id
		}
	}
	panic("benchmark syscall is missing: " + name)
}

func benchmarkTraceEventV2Sample(
	eventType uint16,
	sysID uint32,
	tsNs uint64,
	duration uint64,
	ret int64,
) []byte {
	bodyLen := traceEventV2EnterBodyLen
	if eventType == bpfEventTypeExit {
		bodyLen = traceEventV2ExitBodyLen
	}
	raw := make([]byte, traceEventV2HeaderLen+bodyLen)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderVersionOffset:traceEventV2HeaderVersionOffset+traceEventV2U16Size], traceEventV2Version)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderEventTypeOffset:traceEventV2HeaderEventTypeOffset+traceEventV2U16Size], eventType)
	flags := uint16(0)
	if eventType == bpfEventTypeEnter {
		flags = uint16(bpfEventFlagGenericEnter)
	}
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderFlagsOffset:traceEventV2HeaderFlagsOffset+traceEventV2U16Size], flags)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderLenOffset:traceEventV2HeaderLenOffset+traceEventV2U16Size], traceEventV2HeaderLen)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderSizeOffset:traceEventV2HeaderSizeOffset+traceEventV2U32Size], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderPIDOffset:traceEventV2HeaderPIDOffset+traceEventV2U32Size], 101)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderTIDOffset:traceEventV2HeaderTIDOffset+traceEventV2U32Size], 101)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderSysIDOffset:traceEventV2HeaderSysIDOffset+traceEventV2U32Size], sysID)
	binary.LittleEndian.PutUint64(raw[traceEventV2HeaderTSNSOffset:traceEventV2HeaderTSNSOffset+traceEventV2U64Size], tsNs)

	bodyOffset := traceEventV2HeaderLen
	binary.LittleEndian.PutUint64(raw[bodyOffset+traceEventV2EnterRetOffset:bodyOffset+traceEventV2EnterRetOffset+traceEventV2U64Size], uint64(ret))
	if eventType == bpfEventTypeEnter {
		binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2EnterCaptureLenOffset:bodyOffset+traceEventV2EnterCaptureLenOffset+traceEventV2U32Size], 0)
		return raw
	}
	binary.LittleEndian.PutUint64(raw[bodyOffset+traceEventV2ExitDurationOffset:bodyOffset+traceEventV2ExitDurationOffset+traceEventV2U64Size], duration)
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2ExitCaptureLenOffset:bodyOffset+traceEventV2ExitCaptureLenOffset+traceEventV2U32Size], 0)
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2ExitStackIDOffset:bodyOffset+traceEventV2ExitStackIDOffset+traceEventV2U32Size], 0)
	return raw
}
