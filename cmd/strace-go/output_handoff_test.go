package main

import (
	"bytes"
	"testing"
)

func TestOutputHandoffClosesBeforeTransfer(t *testing.T) {
	events := make([]string, 0, 1)
	closer := &fakeTraceOutputCloser{events: &events}
	output, err := newTraceOutput(TraceOutputDeps{Writer: bytes.NewBuffer(nil), Closer: closer})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	handoff, err := newTraceOutputHandoff(output)
	if err != nil {
		t.Fatalf("newTraceOutputHandoff() error = %v", err)
	}
	if err := handoff.Close(); err != nil {
		t.Fatalf("handoff.Close() error = %v", err)
	}
	if closer.closeCall != 1 {
		t.Fatalf("close calls = %d, want 1", closer.closeCall)
	}
}

func TestOutputHandoffTransferLeavesCloseToSession(t *testing.T) {
	events := make([]string, 0, 1)
	closer := &fakeTraceOutputCloser{events: &events}
	output, err := newTraceOutput(TraceOutputDeps{Writer: bytes.NewBuffer(nil), Closer: closer})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	handoff, err := newTraceOutputHandoff(output)
	if err != nil {
		t.Fatalf("newTraceOutputHandoff() error = %v", err)
	}
	if err := handoff.Transfer(); err != nil {
		t.Fatalf("handoff.Transfer() error = %v", err)
	}
	if err := handoff.Close(); err != nil {
		t.Fatalf("handoff.Close() after transfer error = %v", err)
	}
	if closer.closeCall != 0 {
		t.Fatalf("handoff close calls after transfer = %d, want 0", closer.closeCall)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("session output Close() error = %v", err)
	}
	if closer.closeCall != 1 {
		t.Fatalf("session close calls = %d, want 1", closer.closeCall)
	}
}

func TestOutputHandoffRejectsRepeatedTransfer(t *testing.T) {
	output, err := newTraceOutput(TraceOutputDeps{Writer: bytes.NewBuffer(nil)})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	handoff, err := newTraceOutputHandoff(output)
	if err != nil {
		t.Fatalf("newTraceOutputHandoff() error = %v", err)
	}
	if err := handoff.Transfer(); err != nil {
		t.Fatalf("first Transfer() error = %v", err)
	}
	if err := handoff.Transfer(); err == nil {
		t.Fatal("second Transfer() returned nil error")
	}
	if err := output.Close(); err != nil {
		t.Fatalf("output Close() error = %v", err)
	}
}
