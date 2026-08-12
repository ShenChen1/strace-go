package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

func TestJSONEventWriterWithoutOutputIsNoop(t *testing.T) {
	writer := newJSONEventWriter(JSONEventWriterDeps{})

	writer.WriteRaw(syscallEventContext{})
	writer.WriteDecoded(syscallEventContext{}, handler.Result{})
	writer.WriteLifecycle(lifecycleEventView{}, nil)
}

func TestTraceSessionEmitsDebugReadyEvent(t *testing.T) {
	var output bytes.Buffer
	session := newTraceSession(traceSessionDeps{
		Opts:      &cli.Options{DebugEvents: true},
		TargetPID: 42,
		OutWriter: &output,
	})
	session.opts.AttachPids = []int{42, 84}

	session.emitDebugReady()

	var event jsonReadyEvent
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode ready event: %v", err)
	}
	if event.Type != "ready" || event.TargetPID != 42 {
		t.Fatalf("ready event = %+v, want target 42", event)
	}
	if len(event.AttachPIDs) != 2 || event.AttachPIDs[1] != 84 {
		t.Fatalf("attach pids = %v, want [42 84]", event.AttachPIDs)
	}
}

func TestTraceSessionDoesNotEmitReadyOutsideDebugMode(t *testing.T) {
	var output bytes.Buffer
	session := newTraceSession(traceSessionDeps{
		Opts:      &cli.Options{EventFormat: cli.EventFormatJSON},
		TargetPID: 42,
		OutWriter: &output,
	})

	session.emitDebugReady()

	if output.Len() != 0 {
		t.Fatalf("ordinary JSON output contains debug ready event: %q", output.String())
	}
}
