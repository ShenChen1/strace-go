package main

import (
	"bytes"
	"errors"
	"testing"
)

type fakeTraceOutputCloser struct {
	events    *[]string
	closeErr  error
	closeCall int
}

func (c *fakeTraceOutputCloser) Close() error {
	c.closeCall++
	*c.events = append(*c.events, "close-writer")
	return c.closeErr
}

type fakeTraceOutputWaiter struct {
	events   *[]string
	waitErr  error
	waitCall int
}

func (w *fakeTraceOutputWaiter) Wait() error {
	w.waitCall++
	*w.events = append(*w.events, "wait-command")
	return w.waitErr
}

func TestTraceOutputOwnsWriterAndWaitsAfterClose(t *testing.T) {
	var out bytes.Buffer
	events := make([]string, 0, 2)
	closer := &fakeTraceOutputCloser{events: &events}
	waiter := &fakeTraceOutputWaiter{events: &events}
	output, err := newTraceOutput(TraceOutputDeps{
		Writer:  &out,
		Closer:  closer,
		Command: waiter,
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}

	if _, err := output.Write([]byte("trace\n")); err != nil {
		t.Fatalf("TraceOutput.Write() error = %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("TraceOutput.Close() error = %v", err)
	}
	if got := out.String(); got != "trace\n" {
		t.Fatalf("output = %q, want trace line", got)
	}
	if closer.closeCall != 1 || waiter.waitCall != 1 {
		t.Fatalf("close calls = %d, wait calls = %d, want one each", closer.closeCall, waiter.waitCall)
	}
	if got, want := events, []string{"close-writer", "wait-command"}; !equalStrings(got, want) {
		t.Fatalf("resource order = %v, want %v", got, want)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("second TraceOutput.Close() error = %v, want nil", err)
	}
	if closer.closeCall != 1 || waiter.waitCall != 1 {
		t.Fatalf("second close repeated resources: close=%d wait=%d", closer.closeCall, waiter.waitCall)
	}
}

func TestTraceOutputCloseJoinsCloseErrors(t *testing.T) {
	closeErr := errors.New("writer close failed")
	waitErr := errors.New("output command failed")
	events := make([]string, 0, 2)
	output, err := newTraceOutput(TraceOutputDeps{
		Writer:  bytes.NewBuffer(nil),
		Closer:  &fakeTraceOutputCloser{events: &events, closeErr: closeErr},
		Command: &fakeTraceOutputWaiter{events: &events, waitErr: waitErr},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}

	err = output.Close()
	if !errors.Is(err, closeErr) || !errors.Is(err, waitErr) {
		t.Fatalf("TraceOutput.Close() error = %v, want both resource errors", err)
	}
}

func TestTraceOutputRejectsWriteAfterClose(t *testing.T) {
	output, err := newTraceOutput(TraceOutputDeps{Writer: bytes.NewBuffer(nil)})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("TraceOutput.Close() error = %v", err)
	}
	if _, err := output.Write([]byte("late")); err == nil {
		t.Fatal("TraceOutput.Write() accepted data after Close()")
	}
}

func TestNewTraceOutputRejectsNilWriter(t *testing.T) {
	if _, err := newTraceOutput(TraceOutputDeps{}); err == nil {
		t.Fatal("newTraceOutput() returned nil error for nil writer")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
