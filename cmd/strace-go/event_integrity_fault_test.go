package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cilium/ebpf/ringbuf"
	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

// Fault selection exists only in test binaries, before the production reader.
type integrityFaultStream struct {
	reader    *TraceEventReader
	sequence  uint64
	lossEpoch uint64
	every     uint64
	next      bool
	match     func(traceEventEnvelope) bool
}

func (f *integrityFaultStream) emit(t *testing.T, raw []byte) {
	t.Helper()
	f.sequence++
	binary.LittleEndian.PutUint64(raw[traceEventV2HeaderSeqOffset:], f.sequence)
	binary.LittleEndian.PutUint64(raw[traceEventV2HeaderLossEpochOffset:], f.lossEpoch)
	ev, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("fault stream received invalid fixture")
	}
	selected := f.match == nil || f.match(ev)
	if selected && (f.next || (f.every != 0 && f.sequence%f.every == 0)) {
		f.next = false
		f.lossEpoch++
		return
	}
	if !f.reader.HandleRecord(&ringbuf.Record{RawSample: raw}) {
		t.Fatal("valid record was rejected")
	}
}

func TestIntegrityDeterministicFaultMatrix(t *testing.T) {
	cases := []struct {
		name    string
		kind    uint16
		action  uint32
		syscall string
		flags   uint32
	}{
		{"enter", bpfEventTypeEnter, 0, "read", bpfEventFlagGenericEnter},
		{"exit", bpfEventTypeExit, 0, "read", 0},
		{"path fragment", bpfEventTypeEnter, 0, "read", bpfEventFlagEnterFragment},
		{"close", bpfEventTypeExit, 0, "close", 0},
		{"dup", bpfEventTypeExit, 0, "dup", 0},
		{"fork", bpfEventTypeLifecycle, lifecycleFork, "", 0},
		{"exec", bpfEventTypeLifecycle, lifecycleExec, "", 0},
		{"task exit", bpfEventTypeLifecycle, lifecycleExit, "", 0},
		{"task free", bpfEventTypeLifecycle, lifecycleFree, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &TraceState{}
			fd := newFDStateStore(map[string]string{"10:5": "/wrong", "20:5": "/shared"})
			warnings := 0
			i := newTraceIntegrity(traceIntegrityDeps{State: state, FDState: fd, Notify: func(traceIntegritySnapshot) { warnings++ }})
			router := newTraceEventRouter(TraceEventRouterDeps{State: state})
			stream := integrityFaultStream{reader: newTraceEventReader(TraceEventReaderDeps{
				Decoder: newTraceRingbufRecordDecoder(), Integrity: i, Sink: router})}
			spec := traceEventV2SampleSpec{pid: 10, tid: 11, sysID: syscallIDByName(t, "read"), tsNs: 100, flags: bpfEventFlagGenericEnter}
			stream.emit(t, traceEventV2EnterSample(t, spec))
			spec.flags, spec.action = tc.flags, tc.action
			if tc.syscall != "" {
				spec.sysID = syscallIDByName(t, tc.syscall)
			}
			stream.next = true
			stream.match = func(ev traceEventEnvelope) bool { return ev.eventType == tc.kind }
			var lost []byte
			switch tc.kind {
			case bpfEventTypeEnter:
				lost = traceEventV2EnterSample(t, spec)
			case bpfEventTypeExit:
				lost = traceEventV2ExitSample(t, spec)
			default:
				lost = traceEventV2LifecycleSample(t, spec)
			}
			stream.emit(t, lost)
			spec.flags, spec.sysID = 0, syscallIDByName(t, "read")
			stream.emit(t, traceEventV2ExitSample(t, spec))
			if warnings != 1 || i.Snapshot().EstimatedLost != 1 || !fd.tainted || state.PendingStaleCount() != 0 {
				t.Fatalf("failed degradation: warnings=%d integrity=%+v", warnings, i.Snapshot())
			}
			if path, ok := fd.Path(20, 5); ok {
				t.Fatalf("shared history survived: %s", path)
			}
			spec.tsNs, spec.flags = 200, bpfEventFlagGenericEnter
			stream.emit(t, traceEventV2EnterSample(t, spec))
			spec.flags = 0
			stream.emit(t, traceEventV2ExitSample(t, spec))
			if i.Snapshot().RecoveredDomains != 1 || i.correlationTainted(11) {
				t.Fatalf("recovery failed: %+v", i.Snapshot())
			}
		})
	}
}

func TestIntegrityFDHistoryNeverRevivesButCurrentSnapshotRenders(t *testing.T) {
	fd := newFDStateStore(map[string]string{"10:5": "/wrong", "10:cwd": "/wrong-cwd"})
	fd.TaintHistory()
	fd.InheritProcessState(10, 20)
	fd.CloseOnExecProcess(10)
	opts := cli.ParseArgs([]string{"-y", "/bin/true"})
	deps := syscallEventContextDeps{decoder: event.NewDecoder(), handlerOpts: opts, filter: newTraceFilterOptions(opts), fdState: fd}
	view := syscallEventView{valid: true, pid: 10, tid: 11, sysID: syscallIDByName(t, "dup"), eventType: bpfEventTypeExit, args: [6]uint64{5}, ret: 7}
	for _, snapshot := range []bool{false, true, false} {
		var sections []handler.PayloadSection
		if snapshot {
			sections = []handler.PayloadSection{{Kind: handler.PayloadKindFDPath, Direction: handler.PayloadDirectionIn, ArgIndex: 0, Data: []byte("/observed\x00")}}
		}
		ev := newSyscallEventContextFromViewWithDeps(deps, view, 10, nil, sections)
		want := "5"
		if snapshot {
			want = "5</observed>"
		}
		if got := handler.FormatFdWithPath(ev.handlerContext, 5); got != want {
			t.Fatalf("fd text=%q want=%q", got, want)
		}
		ev.updateFDState(fd)
		ev.releaseHandlerContext()
	}
	if _, ok := fd.Cwd(10); ok {
		t.Fatal("cwd revived")
	}
	if _, ok := fd.Path(20, 5); ok {
		t.Fatal("fork restored tainted state")
	}
}

func TestIntegrityBurstWrapSummaryAndWarningRate(t *testing.T) {
	var warning bytes.Buffer
	i := newTraceIntegrity(traceIntegrityDeps{Notify: traceIntegrityReporter(nil, nil, &warning)})
	i.cpus[0] = traceCPUSequence{sequence: ^uint64(0) - 2}
	for _, item := range []struct {
		seq       uint64
		lossEpoch uint64
	}{
		{^uint64(0) - 1, 0}, {^uint64(0), 0}, {0, 0}, {1, 0},
		{5, 1}, {6, 1}, {9, 2},
	} {
		ev := traceEventEnvelope{pid: 10, tid: 11, seq: item.seq, lossEpoch: item.lossEpoch}
		i.Observe(&ev)
	}
	s := i.Snapshot()
	if s.StreamGaps != 2 || s.EstimatedLost != 5 || s.SequenceReorders != 0 {
		t.Fatalf("gap accounting: %+v", s)
	}
	if strings.Count(warning.String(), "WARNING") != 1 {
		t.Fatalf("warnings=%q", warning.String())
	}
	var summary bytes.Buffer
	writeIntegritySummary(&summary, s, bpfRuntimeStats{Available: true, RingbufReserveFail: 7})
	for _, want := range []string{"stream_gaps=2", "estimated_lost_events=5", "ringbuf_reserve_fail=7", "fd_state"} {
		if !strings.Contains(summary.String(), want) {
			t.Fatalf("summary lacks %q: %s", want, summary.String())
		}
	}
	ev := traceEventEnvelope{tainted: true, correlationTainted: true, integrityEpoch: 2}
	raw := appendJSONRecordIntegrity([]byte(`{"type":"syscall"`), ev.recordIntegrity())
	raw = append(raw, '}')
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["integrity_epoch"] != float64(2) || len(fields["tainted_domains"].([]any)) != 4 {
		t.Fatalf("record trust: %s", raw)
	}
}

func TestIntegrityMachineDiagnosticModesWriteJSON(t *testing.T) {
	cases := []struct {
		name string
		opts cli.Options
	}{
		{name: "none", opts: cli.Options{EventFormat: cli.EventFormatNone}},
		{name: "reader", opts: cli.Options{EventFormat: cli.EventFormatReader}},
		{name: "handler", opts: cli.Options{EventFormat: cli.EventFormatHandler}},
		{name: "debug phases", opts: cli.Options{EventFormat: cli.EventFormatText, DebugPhases: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var diagnostic bytes.Buffer
			report := traceIntegrityReporter(newTraceOutputPolicy(&tc.opts), nil, &diagnostic)
			report(traceIntegritySnapshot{Tainted: true, Scope: "session", Reason: "producer_loss"})

			var event struct {
				Type    string `json:"type"`
				Tainted bool   `json:"tainted"`
				Reason  string `json:"reason"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(diagnostic.Bytes()), &event); err != nil {
				t.Fatalf("decode integrity diagnostic JSON: %v; output=%q", err, diagnostic.String())
			}
			if event.Type != "integrity" || !event.Tainted || event.Reason != "producer_loss" {
				t.Fatalf("integrity diagnostic = %+v", event)
			}
		})
	}
}

func TestIntegrityEveryNthAndTail(t *testing.T) {
	i := newTraceIntegrity(traceIntegrityDeps{})
	f := integrityFaultStream{every: 3, reader: newTraceEventReader(TraceEventReaderDeps{Decoder: newTraceRingbufRecordDecoder(), Integrity: i})}
	for n := 0; n < 9; n++ {
		f.emit(t, traceEventV2ExitSample(t, traceEventV2SampleSpec{pid: 10, tid: 10}))
	}
	if i.Snapshot().EstimatedLost != 2 {
		t.Fatal("wrong observed gaps before trailing drop")
	}
	i.Finalize(bpfRuntimeStats{Available: true, EventSequences: []uint64{9}})
	if i.Snapshot().Reason != "sequence_tail_at_finalization" {
		t.Fatalf("tail missed: %+v", i.Snapshot())
	}
}
