package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

type fakeRunFinalizerPipe struct {
	bytes.Buffer
	closed bool
}

type recordingOutputWriter struct {
	writes []string
}

func (w *recordingOutputWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

type fakePendingStateReader struct {
	stale int
}

type fakeEventReaderStatsReader struct {
	stats traceEventReaderStats
}

func (r fakeEventReaderStatsReader) ReaderStats() traceEventReaderStats {
	return r.stats
}

type recordingTraceDebugPhasePort struct {
	events *[]string
}

func (p *recordingTraceDebugPhasePort) EmitPhase(phase string) {
	*p.events = append(*p.events, "phase:"+phase)
}

func (p *recordingTraceDebugPhasePort) EmitPhaseAt(phase string, _, _ uint64) {
	p.EmitPhase(phase)
}

func (r fakePendingStateReader) PendingStaleCount() int {
	return r.stale
}

func TestTraceRunFinalizerEmitsCleanupPhaseBeforeOutputClose(t *testing.T) {
	events := make([]string, 0, 2)
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: bytes.NewBuffer(nil),
		Closer: &fakeTraceOutputCloser{events: &events},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		DebugPhases: &recordingTraceDebugPhasePort{events: &events},
		Output:      output,
	})

	if err := finalizer.Finish(); err != nil {
		t.Fatalf("TraceRunFinalizer.Finish() error = %v", err)
	}
	if got, want := events, []string{"phase:cleanup_start", "close-writer"}; !equalStrings(got, want) {
		t.Fatalf("finalizer cleanup order = %v, want %v", got, want)
	}
}

func TestTraceRunFinalizerWritesPendingStaleCount(t *testing.T) {
	var out bytes.Buffer
	output, err := newTraceOutput(TraceOutputDeps{Writer: &out})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy: newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatJSON}),
		PendingState: fakePendingStateReader{stale: 3},
		Output:       output,
	})

	if err := finalizer.Finish(); err != nil {
		t.Fatalf("TraceRunFinalizer.Finish() error = %v", err)
	}
	var event struct {
		Type         string `json:"type"`
		PendingStale uint64 `json:"pending_stale"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &event); err != nil {
		t.Fatalf("decode stats JSON: %v", err)
	}
	if event.Type != "stats" || event.PendingStale != 3 {
		t.Fatalf("stats JSON = %+v, want pending_stale=3", event)
	}
}

func TestTraceRunFinalizerFlushesBufferedEventsBeforeStats(t *testing.T) {
	underlying := &recordingOutputWriter{}
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: underlying,
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	if err := output.EnableBuffer(traceOutputBufferSize); err != nil {
		t.Fatalf("TraceOutput.EnableBuffer() error = %v", err)
	}
	if _, err := output.Write([]byte("event\\n")); err != nil {
		t.Fatalf("TraceOutput.Write() error = %v", err)
	}

	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy: newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatJSON}),
		Output:       output,
	})
	if err := finalizer.Finish(); err != nil {
		t.Fatalf("TraceRunFinalizer.Finish() error = %v", err)
	}
	if len(underlying.writes) != 2 || underlying.writes[0] != "event\\n" {
		t.Fatalf("buffered writes = %#v, want event before stats", underlying.writes)
	}
	var stats jsonStatsEvent
	if err := json.Unmarshal(bytes.TrimSpace([]byte(underlying.writes[1])), &stats); err != nil {
		t.Fatalf("decode stats write: %v", err)
	}
	if stats.Type != "stats" {
		t.Fatalf("second buffered write type = %q, want stats", stats.Type)
	}
}

func (p *fakeRunFinalizerPipe) Close() error {
	p.closed = true
	return nil
}

func TestTraceRunFinalizerWritesJSONStats(t *testing.T) {
	var out bytes.Buffer
	output, err := newTraceOutput(TraceOutputDeps{Writer: &out})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	policy := newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatJSON})
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy: policy,
		Output:       output,
	})

	finalizer.writeStats(bpfRuntimeStats{
		Available:              true,
		RingbufReserveFail:     5,
		RingbufCopyFail:        6,
		PendingUpdateFail:      7,
		OrphanExit:             8,
		PendingMismatch:        9,
		LifecycleMapUpdateFail: 10,
	})

	var ev jsonStatsEvent
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &ev); err != nil {
		t.Fatalf("decode stats JSON: %v", err)
	}
	if ev.Type != "stats" || ev.RingbufReserveFail != 5 || ev.RingbufCopyFail != 6 ||
		ev.PendingUpdateFail != 7 || ev.OrphanExit != 8 || ev.PendingMismatch != 9 ||
		ev.LifecycleMapUpdateFail != 10 || !ev.Available {
		t.Fatalf("stats JSON = %+v, want populated stats event", ev)
	}
}

func TestTraceRunFinalizerSnapshotsJSONSyscallOutputBeforeStats(t *testing.T) {
	var out bytes.Buffer
	output, err := newTraceOutput(TraceOutputDeps{Writer: &out})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: output})
	writer.WriteRaw(syscallEventContext{
		view: syscallEventView{valid: true, eventType: bpfEventTypeExit, pid: 101, tid: 101, sysID: 39, ret: 101},
	})

	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy: newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatJSON}),
		JSONWriter:   writer,
		Output:       output,
	})
	if err := finalizer.Finish(); err != nil {
		t.Fatalf("TraceRunFinalizer.Finish() error = %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("finalizer JSON lines = %d, want syscall and stats: %q", len(lines), out.String())
	}
	var stats jsonStatsEvent
	if err := json.Unmarshal(lines[1], &stats); err != nil {
		t.Fatalf("decode finalizer stats: %v", err)
	}
	wantBytes := uint64(len(lines[0]) + 1)
	if stats.SyscallOutputBytes != wantBytes || stats.SyscallOutputWrites != 1 || stats.SyscallOutputWriteErrors != 0 {
		t.Fatalf("finalizer JSON output stats = %+v, want bytes=%d writes=1 errors=0", stats, wantBytes)
	}
}

func TestTraceRunFinalizerWritesDiscardStatsToDiagnostic(t *testing.T) {
	var diagnostics bytes.Buffer
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy:    newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatNone}),
		StatsDiagnostic: &diagnostics,
		ReaderStats: fakeEventReaderStatsReader{stats: traceEventReaderStats{
			RecordsRead:       21,
			RecordsDecoded:    19,
			RecordsInvalid:    2,
			RecordsRouted:     19,
			MaxRemainingBytes: 4096,
		}},
	})

	finalizer.writeStats(bpfRuntimeStats{Available: true, RingbufReserveFail: 11})

	var event jsonStatsEvent
	if err := json.Unmarshal(bytes.TrimSpace(diagnostics.Bytes()), &event); err != nil {
		t.Fatalf("decode discard stats JSON: %v", err)
	}
	if event.Type != "stats" || !event.Available || event.RingbufReserveFail != 11 ||
		event.RecordsRead != 21 || event.RecordsDecoded != 19 || event.RecordsInvalid != 2 ||
		event.RecordsRouted != 19 || event.MaxRemainingBytes != 4096 {
		t.Fatalf("discard stats JSON = %+v, want available reserve_fail=11", event)
	}
}

func TestTraceRunFinalizerWritesTextStatsDiagnostic(t *testing.T) {
	var diagnostics bytes.Buffer
	policy := newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatText})
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy:    policy,
		StatsDiagnostic: &diagnostics,
	})

	finalizer.writeStats(bpfRuntimeStats{
		Available:              true,
		RingbufReserveFail:     1,
		RingbufCopyFail:        2,
		PendingUpdateFail:      3,
		OrphanExit:             4,
		OrphanFirstPid:         101,
		OrphanFirstTid:         102,
		OrphanFirstSysID:       39,
		OrphanFirstRet:         101,
		OrphanFirstReason:      1,
		OrphanLastPid:          103,
		OrphanLastTid:          104,
		OrphanLastSysID:        60,
		OrphanLastRet:          -1,
		OrphanLastReason:       1,
		PendingMismatch:        5,
		LifecycleMapUpdateFail: 6,
	})

	got := diagnostics.String()
	for _, want := range []string{
		"ringbuf_reserve_fail=1",
		"ringbuf_copy_fail=2",
		"pending_update_fail=3",
		"orphan_exit=4",
		"pending_mismatch=5",
		"lifecycle_map_update_fail=6",
		"orphan_first=(pid=101 tid=102 sys_id=39 ret=101 reason=1)",
		"orphan_last=(pid=103 tid=104 sys_id=60 ret=-1 reason=1)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("diagnostic = %q, missing %q", got, want)
		}
	}
}

func TestTraceRunFinalizerWritesStructuredTextDebugStats(t *testing.T) {
	var diagnostics bytes.Buffer
	policy := newTraceOutputPolicy(&cli.Options{
		EventFormat: cli.EventFormatText,
		DebugPhases: true,
	})
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy:    policy,
		StatsDiagnostic: &diagnostics,
		ReaderStats: fakeEventReaderStatsReader{stats: traceEventReaderStats{
			RecordsRead:    7,
			RecordsDecoded: 7,
			RecordsRouted:  7,
		}},
	})

	finalizer.writeStats(bpfRuntimeStats{Available: true})

	var event jsonStatsEvent
	if err := json.Unmarshal(bytes.TrimSpace(diagnostics.Bytes()), &event); err != nil {
		t.Fatalf("decode text debug stats JSON: %v; output=%q", err, diagnostics.String())
	}
	if event.Type != "stats" || event.RecordsRead != 7 || !event.Available {
		t.Fatalf("text debug stats = %+v, want structured records=7", event)
	}
}

func TestTraceRunFinalizerPrintsSummaryAndClosesPipe(t *testing.T) {
	var out bytes.Buffer
	pipe := &fakeRunFinalizerPipe{}
	summary := newSummaryStats()
	summary.Record("getpid", 1000, 1000, 0)
	output, err := newTraceOutput(TraceOutputDeps{Writer: &out, Closer: pipe})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	policy := newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatText, SummaryOnly: true})
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy:  policy,
		SummaryPolicy: policy,
		Summary:       summary,
		Output:        output,
	})

	finalizer.Finish()

	if !strings.Contains(out.String(), "getpid") {
		t.Fatalf("summary output = %q, want getpid entry", out.String())
	}
	if !pipe.closed {
		t.Fatal("output pipe was not closed")
	}
}

func TestTraceRunFinalizerFlushesExitFallback(t *testing.T) {
	var out bytes.Buffer
	queue := newExitStatusQueue()
	queue.MarkExitedWithFallback(101, "fallback\n")
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		TargetPID: 101,
		ExitStatus: newExitStatusCoordinator(ExitStatusCoordinatorDeps{
			Queue: queue,
			Out:   &out,
		}),
	})

	finalizer.Finish()

	if out.String() != "fallback\n" {
		t.Fatalf("fallback output = %q, want fallback line", out.String())
	}
}

func TestTraceRunFinalizerReturnsOutputCloseError(t *testing.T) {
	closeErr := errors.New("output close failed")
	events := make([]string, 0, 1)
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: bytes.NewBuffer(nil),
		Closer: &fakeTraceOutputCloser{events: &events, closeErr: closeErr},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{Output: output})

	if err := finalizer.Finish(); !errors.Is(err, closeErr) {
		t.Fatalf("TraceRunFinalizer.Finish() error = %v, want %v", err, closeErr)
	}
}
