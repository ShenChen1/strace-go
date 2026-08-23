package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type flushableJSONOutput struct {
	bytes.Buffer
	flushCalls int
}

func (w *flushableJSONOutput) Flush() error {
	w.flushCalls++
	return nil
}

func TestJSONEventWriterWithoutOutputIsNoop(t *testing.T) {
	writer := newJSONEventWriter(JSONEventWriterDeps{})

	writer.WriteRaw(syscallEventContext{})
	writer.WriteDecoded(syscallEventContext{}, handler.Result{})
	writer.WriteLifecycle(lifecycleEventView{}, nil)
}

func TestJSONEventWriterReusesRawAndDecodedBuffer(t *testing.T) {
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})
	event := syscallEventContext{
		view: syscallEventView{valid: true, pid: 101, tid: 101, sysID: 1},
		meta: meta.Syscall{Name: "write"},
		payloadSections: []handler.PayloadSection{{
			Kind: handler.PayloadKindBytes,
			Data: []byte("payload"),
		}},
	}
	writer.WriteRaw(event)
	capacity := cap(writer.syscallBuffer)
	if capacity == 0 || len(writer.syscallBuffer) == 0 {
		t.Fatalf("raw JSON buffer is empty: len=%d cap=%d", len(writer.syscallBuffer), capacity)
	}

	event.handlerContext = &handler.Context{PayloadSections: event.payloadSections}
	writer.WriteDecoded(event, handler.Result{})
	if cap(writer.syscallBuffer) < capacity || len(writer.syscallBuffer) == 0 {
		t.Fatalf("decoded JSON buffer was not reused: len=%d cap=%d initial_cap=%d", len(writer.syscallBuffer), cap(writer.syscallBuffer), capacity)
	}
}

func TestJSONEventWriterReusesDecodedBuffer(t *testing.T) {
	if raceBuild {
		t.Skip("allocation counts include race instrumentation")
	}
	event := syscallEventContext{
		view: syscallEventView{valid: true, pid: 101, tid: 101, sysID: 1, ret: 7},
		meta: meta.Syscall{Name: "write"},
		handlerContext: &handler.Context{PayloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x2000,
			UserLen:   7,
			CopiedLen: 7,
			Data:      []byte("payload"),
		}}},
	}
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})

	writer.WriteDecoded(event, handler.Result{})
	if len(writer.syscallBuffer) == 0 {
		t.Fatal("decoded JSON buffer is empty")
	}
	allocs := testing.AllocsPerRun(100, func() {
		writer.WriteDecoded(event, handler.Result{})
	})
	if allocs != 0 {
		t.Fatalf("steady-state payload JSON allocations = %.1f, want zero", allocs)
	}
}

func TestJSONEventWriterBatchesOnlyTraceOutputAndPreservesPhaseOrder(t *testing.T) {
	underlying := &countingTraceOutputWriter{}
	output, err := newTraceOutput(TraceOutputDeps{Writer: underlying})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: output})
	event := syscallEventContext{
		view: syscallEventView{valid: true, eventType: bpfEventTypeExit, pid: 101, tid: 101, sysID: 39, ret: 101},
		meta: meta.Syscall{Name: "getpid"},
	}

	writer.WriteRaw(event)
	writer.WriteRaw(event)
	if underlying.writes != 0 {
		t.Fatalf("writes before batch boundary = %d, want 0", underlying.writes)
	}
	writer.WritePhase("trace_start", 7)
	writer.WriteRaw(event)
	if err := writer.Flush(); err != nil {
		t.Fatalf("JSON writer Flush() error = %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(underlying.data.Bytes()), []byte{'\n'})
	if len(lines) != 4 {
		t.Fatalf("JSON output lines = %d, want 4: %q", len(lines), underlying.data.String())
	}
	var first, second, third, fourth struct {
		Type  string `json:"type"`
		Phase string `json:"phase"`
	}
	for index, line := range lines {
		var event struct {
			Type  string `json:"type"`
			Phase string `json:"phase"`
		}
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("decode line %d: %v", index, err)
		}
		switch index {
		case 0:
			first = event
		case 1:
			second = event
		case 2:
			third = event
		case 3:
			fourth = event
		}
	}
	if first.Type != "syscall" || second.Type != "syscall" ||
		third.Type != "phase" || third.Phase != "trace_start" || fourth.Type != "syscall" {
		t.Fatalf("event order = %+v %+v %+v %+v", first, second, third, fourth)
	}
	if underlying.writes != 3 {
		t.Fatalf("underlying writes = %d, want batch/phase/batch", underlying.writes)
	}
}

func TestJSONEventWriterReportsSyscallOutputStats(t *testing.T) {
	underlying := &countingTraceOutputWriter{}
	output, err := newTraceOutput(TraceOutputDeps{Writer: underlying})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: output})
	event := syscallEventContext{
		view: syscallEventView{valid: true, eventType: bpfEventTypeExit, pid: 101, tid: 101, sysID: 39, ret: 101},
		meta: meta.Syscall{Name: "getpid"},
	}

	writer.WriteRaw(event)
	writer.WriteRaw(event)
	writer.WritePhase("trace_start", 7)
	writer.WriteRaw(event)
	if err := writer.Flush(); err != nil {
		t.Fatalf("JSON writer Flush() error = %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(underlying.data.Bytes()), []byte{'\n'})
	var wantBytes uint64
	for _, line := range lines {
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &header); err != nil {
			t.Fatalf("decode output line: %v", err)
		}
		if header.Type == "syscall" {
			wantBytes += uint64(len(line) + 1)
		}
	}
	stats := writer.JSONOutputStats()
	if stats.SyscallBytesWritten != wantBytes || stats.SyscallWriteCalls != 2 || stats.SyscallWriteErrors != 0 {
		t.Fatalf("JSON syscall output stats = %+v, want bytes=%d writes=2 errors=0", stats, wantBytes)
	}
}

func TestJSONEventWriterReportsSyscallOutputError(t *testing.T) {
	writeErr := errors.New("syscall output failed")
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: &fakeTraceOutputWriter{writeErr: writeErr, maxBytes: -1},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: output})
	writer.WriteRaw(syscallEventContext{
		view: syscallEventView{valid: true, eventType: bpfEventTypeExit, pid: 101, tid: 101, sysID: 39, ret: 101},
		meta: meta.Syscall{Name: "getpid"},
	})
	wantBytes := len(writer.syscallBuffer)
	if err := writer.Flush(); err != nil {
		t.Fatalf("JSON writer Flush() error = %v", err)
	}
	stats := writer.JSONOutputStats()
	if stats.SyscallBytesWritten != uint64(wantBytes) || stats.SyscallWriteCalls != 1 || stats.SyscallWriteErrors != 1 {
		t.Fatalf("JSON syscall output error stats = %+v, want bytes=%d writes=1 errors=1", stats, wantBytes)
	}
	if err := output.Close(); !errors.Is(err, writeErr) {
		t.Fatalf("TraceOutput.Close() error = %v, want %v", err, writeErr)
	}
}

func TestJSONEventWriterMeasuresSyscallWriteTimeWhenEnabled(t *testing.T) {
	var output bytes.Buffer
	clock := &diagnosticTraceClock{
		now:    time.Unix(100, 0),
		monoNS: []uint64{100, 145},
	}
	writer := newJSONEventWriter(JSONEventWriterDeps{
		Out:                  &output,
		Clock:                clock,
		MeasureSyscallWrites: true,
	})
	writer.WriteRaw(syscallEventContext{
		view: syscallEventView{valid: true, eventType: bpfEventTypeExit, pid: 101, tid: 101, sysID: 39, ret: 101},
		meta: meta.Syscall{Name: "getpid"},
	})

	stats := writer.JSONOutputStats()
	if stats.SyscallWriteTimeNS != 45 || stats.SyscallWriteTimeSamples != 1 || clock.monoCall != 2 {
		t.Fatalf("JSON write timing = %+v, clock calls=%d; want 45ns/1 sample", stats, clock.monoCall)
	}
}

func TestJSONEventWriterSkipsSyscallWriteClockWhenDisabled(t *testing.T) {
	var output bytes.Buffer
	clock := &diagnosticTraceClock{
		now:    time.Unix(100, 0),
		monoNS: []uint64{100, 145},
	}
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: &output, Clock: clock})
	writer.WriteRaw(syscallEventContext{
		view: syscallEventView{valid: true, eventType: bpfEventTypeExit, pid: 101, tid: 101, sysID: 39, ret: 101},
		meta: meta.Syscall{Name: "getpid"},
	})

	stats := writer.JSONOutputStats()
	if stats.SyscallWriteTimeNS != 0 || stats.SyscallWriteTimeSamples != 0 || clock.monoCall != 0 {
		t.Fatalf("disabled JSON write timing = %+v, clock calls=%d; want no timing", stats, clock.monoCall)
	}
}

func TestTraceRunFinalizerFlushesJSONSyscallTail(t *testing.T) {
	var out bytes.Buffer
	output, err := newTraceOutput(TraceOutputDeps{Writer: &out})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: output})
	writer.WriteRaw(syscallEventContext{
		view: syscallEventView{valid: true, eventType: bpfEventTypeExit, pid: 101, tid: 101, sysID: 39, ret: 101},
		meta: meta.Syscall{Name: "getpid"},
	})
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		JSONWriter: writer,
		Output:     output,
	})
	if err := finalizer.Finish(); err != nil {
		t.Fatalf("TraceRunFinalizer.Finish() error = %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"type":"syscall"`)) {
		t.Fatalf("finalizer dropped JSON syscall tail: %q", out.String())
	}
}

func TestTraceSessionEmitsDebugReadyEvent(t *testing.T) {
	var output bytes.Buffer
	session := newTestTraceSessionWithOptions(&cli.Options{DebugEvents: true, AttachPids: []int{42, 84}}, traceSessionDeps{
		TargetPID: 42,
		OutWriter: &output,
		Clock:     &fakeTraceClock{monoNs: 99},
	})

	session.emitDebugReadyAt(7)

	var event jsonReadyEvent
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode ready event: %v", err)
	}
	if event.Type != "ready" || event.TargetPID != 42 || event.StartTimeNS != 7 || event.TimeNS != 99 {
		t.Fatalf("ready event = %+v, want target 42", event)
	}
	if len(event.AttachPIDs) != 2 || event.AttachPIDs[1] != 84 {
		t.Fatalf("attach pids = %v, want [42 84]", event.AttachPIDs)
	}
}

func TestTraceSessionFlushesDebugReadyEvent(t *testing.T) {
	output := &flushableJSONOutput{}
	session := newTestTraceSessionWithOptions(&cli.Options{DebugEvents: true}, traceSessionDeps{
		OutWriter: output,
	})

	session.emitDebugReadyAt(7)

	if output.flushCalls != 1 {
		t.Fatalf("ready flush calls = %d, want 1", output.flushCalls)
	}
}

func TestTraceSessionEmitsDebugPhaseEvent(t *testing.T) {
	var output bytes.Buffer
	session := newTestTraceSessionWithOptions(&cli.Options{DebugPhases: true}, traceSessionDeps{
		OutWriter: &output,
		Clock:     &fakeTraceClock{monoNs: 123},
	})

	session.emitDebugPhase("trace_start")

	var event jsonPhaseEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("decode phase event: %v", err)
	}
	if event.Type != "phase" || event.Phase != "trace_start" || event.TimeNS != 123 || event.DurationNS != 0 {
		t.Fatalf("phase event = %+v, want trace_start at 123ns", event)
	}
}

func TestTraceSessionEmitsBPFSetupPhaseDuration(t *testing.T) {
	var output bytes.Buffer
	session := newTestTraceSessionWithOptions(&cli.Options{DebugPhases: true}, traceSessionDeps{
		OutWriter: &output,
	})

	session.emitDebugBPFSetupPhases([]traceBPFSetupTiming{{
		Stage:   bpfSetupCoreCollectionStage,
		StartNS: 10,
		EndNS:   25,
	}})

	var event jsonPhaseEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("decode BPF setup phase event: %v", err)
	}
	if event.Phase != string(bpfSetupCoreCollectionStage) || event.StartTimeNS != 10 || event.DurationNS != 15 {
		t.Fatalf("phase event = %+v, want collection load duration 15ns", event)
	}
}

func TestTraceSessionDoesNotEmitPhaseForRawDebugMode(t *testing.T) {
	var output bytes.Buffer
	session := newTestTraceSessionWithOptions(&cli.Options{DebugEvents: true}, traceSessionDeps{
		OutWriter: &output,
		Clock:     &fakeTraceClock{monoNs: 123},
	})

	session.emitDebugPhase("trace_start")

	if output.Len() != 0 {
		t.Fatalf("raw debug mode contains phase event: %q", output.String())
	}
}

func TestTraceSessionDoesNotEmitDebugPhaseOutsideDebugMode(t *testing.T) {
	var output bytes.Buffer
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatJSON}, traceSessionDeps{
		OutWriter: &output,
	})

	session.emitDebugPhase("trace_start")

	if output.Len() != 0 {
		t.Fatalf("ordinary JSON output contains debug phase event: %q", output.String())
	}
}

func TestTraceSessionDoesNotEmitReadyOutsideDebugMode(t *testing.T) {
	var output bytes.Buffer
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatJSON}, traceSessionDeps{
		TargetPID: 42,
		OutWriter: &output,
	})

	session.emitDebugReady()

	if output.Len() != 0 {
		t.Fatalf("ordinary JSON output contains debug ready event: %q", output.String())
	}
}
