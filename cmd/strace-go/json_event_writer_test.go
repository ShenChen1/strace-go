package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONEventWriterWithoutOutputIsNoop(t *testing.T) {
	writer := newJSONEventWriter(JSONEventWriterDeps{})

	writer.WriteRaw(syscallEventContext{})
	writer.WriteDecoded(syscallEventContext{}, handler.Result{})
	writer.WriteLifecycle(lifecycleEventView{}, nil)
}

func TestJSONEventWriterClearsReusableEventStorage(t *testing.T) {
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})
	writer.WriteRaw(syscallEventContext{
		view: syscallEventView{valid: true, pid: 101, tid: 101, sysID: 1},
		meta: meta.Syscall{Name: "write"},
		payloadSections: []handler.PayloadSection{{
			Kind: handler.PayloadKindBytes,
			Data: []byte("payload"),
		}},
	})
	if writer.syscallEvent.PayloadSections != nil || writer.syscallEvent.Syscall != "" {
		t.Fatalf("syscall storage retained event data: %+v", writer.syscallEvent)
	}

	writer.WriteLifecycle(lifecycleEventView{
		action:       lifecycleExec,
		snapshotText: "/bin/true",
	}, nil)
	if writer.lifecycleEvent != (jsonLifecycleEvent{}) {
		t.Fatalf("lifecycle storage retained event data: %+v", writer.lifecycleEvent)
	}
}

func TestJSONEventWriterReusesPayloadSectionStorage(t *testing.T) {
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
	if cap(writer.payloadSections) != 1 {
		t.Fatalf("payload storage capacity = %d, want 1", cap(writer.payloadSections))
	}
	if len(writer.payloadSections) != 0 || writer.payloadSections[:1][0] != (jsonPayloadSection{}) {
		t.Fatalf("payload storage retained encoded data: len=%d value=%+v", len(writer.payloadSections), writer.payloadSections[:1][0])
	}
	allocs := testing.AllocsPerRun(100, func() {
		writer.WriteDecoded(event, handler.Result{})
	})
	if allocs >= 2 {
		t.Fatalf("steady-state payload JSON allocations = %.1f, want fewer than two", allocs)
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
		Stage:   bpfSetupCollectionLoadStage,
		StartNS: 10,
		EndNS:   25,
	}})

	var event jsonPhaseEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("decode BPF setup phase event: %v", err)
	}
	if event.Phase != string(bpfSetupCollectionLoadStage) || event.StartTimeNS != 10 || event.DurationNS != 15 {
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
