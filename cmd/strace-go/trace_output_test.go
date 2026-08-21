package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type fakeTraceOutputWriter struct {
	writeErr error
	maxBytes int
}

type countingTraceOutputWriter struct {
	data   bytes.Buffer
	writes int
}

func (w *countingTraceOutputWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.data.Write(p)
}

type fakeTraceOutputFlusher struct {
	events   *[]string
	flushErr error
}

func (f *fakeTraceOutputFlusher) Flush() error {
	*f.events = append(*f.events, "flush-output")
	return f.flushErr
}

func (w *fakeTraceOutputWriter) Write(p []byte) (int, error) {
	if w.maxBytes >= 0 && len(p) > w.maxBytes {
		return w.maxBytes, w.writeErr
	}
	return len(p), w.writeErr
}

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

func TestTraceOutputFlushesBeforeClosingWriter(t *testing.T) {
	events := make([]string, 0, 2)
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: bytes.NewBuffer(nil),
		Flush:  (&fakeTraceOutputFlusher{events: &events}).Flush,
		Closer: &fakeTraceOutputCloser{events: &events},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}

	if err := output.Close(); err != nil {
		t.Fatalf("TraceOutput.Close() error = %v", err)
	}
	if got, want := events, []string{"flush-output", "close-writer"}; !equalStrings(got, want) {
		t.Fatalf("flush/close order = %v, want %v", got, want)
	}
}

func TestTraceOutputCloseJoinsFlushError(t *testing.T) {
	flushErr := errors.New("output flush failed")
	events := make([]string, 0, 2)
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: bytes.NewBuffer(nil),
		Flush:  (&fakeTraceOutputFlusher{events: &events, flushErr: flushErr}).Flush,
		Closer: &fakeTraceOutputCloser{events: &events},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}

	if err := output.Close(); !errors.Is(err, flushErr) {
		t.Fatalf("TraceOutput.Close() error = %v, want %v", err, flushErr)
	}
	if got, want := events, []string{"flush-output", "close-writer"}; !equalStrings(got, want) {
		t.Fatalf("flush error cleanup order = %v, want %v", got, want)
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

func TestTraceOutputCapturesWriteErrorUntilClose(t *testing.T) {
	writeErr := errors.New("output write failed")
	events := make([]string, 0, 1)
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: &fakeTraceOutputWriter{writeErr: writeErr, maxBytes: -1},
		Closer: &fakeTraceOutputCloser{events: &events},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	if _, err := output.Write([]byte("trace\n")); !errors.Is(err, writeErr) {
		t.Fatalf("TraceOutput.Write() error = %v, want %v", err, writeErr)
	}
	if err := output.Close(); !errors.Is(err, writeErr) {
		t.Fatalf("TraceOutput.Close() error = %v, want %v", err, writeErr)
	}
	if got, want := events, []string{"close-writer"}; !equalStrings(got, want) {
		t.Fatalf("resource cleanup after write error = %v, want %v", got, want)
	}
}

func TestTraceOutputNormalizesShortWrite(t *testing.T) {
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: &fakeTraceOutputWriter{maxBytes: 1},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	n, err := output.Write([]byte("trace"))
	if n != 1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("TraceOutput.Write() = (%d, %v), want (1, io.ErrShortWrite)", n, err)
	}
	if err := output.Close(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("TraceOutput.Close() error = %v, want io.ErrShortWrite", err)
	}
}

func TestTraceOutputWriteBatchFlushesBufferedPrefix(t *testing.T) {
	var out bytes.Buffer
	output, err := newTraceOutput(TraceOutputDeps{Writer: &out})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	if err := output.EnableBuffer(8); err != nil {
		t.Fatalf("EnableBuffer() error = %v", err)
	}
	if _, err := output.Write([]byte("prefix")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := output.WriteBatch([]byte("batch")); err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	}
	if got, want := out.String(), "prefixbatch"; got != want {
		t.Fatalf("batched output = %q, want %q", got, want)
	}
}

func TestTraceOutputCloseJoinsWriteCloseAndWaitErrors(t *testing.T) {
	writeErr := errors.New("output write failed")
	closeErr := errors.New("writer close failed")
	waitErr := errors.New("output command failed")
	events := make([]string, 0, 2)
	output, err := newTraceOutput(TraceOutputDeps{
		Writer:  &fakeTraceOutputWriter{writeErr: writeErr, maxBytes: -1},
		Closer:  &fakeTraceOutputCloser{events: &events, closeErr: closeErr},
		Command: &fakeTraceOutputWaiter{events: &events, waitErr: waitErr},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	if _, err := output.Write([]byte("trace")); !errors.Is(err, writeErr) {
		t.Fatalf("TraceOutput.Write() error = %v, want %v", err, writeErr)
	}
	err = output.Close()
	if !errors.Is(err, writeErr) || !errors.Is(err, closeErr) || !errors.Is(err, waitErr) {
		t.Fatalf("TraceOutput.Close() error = %v, want write/close/wait errors", err)
	}
	if got, want := events, []string{"close-writer", "wait-command"}; !equalStrings(got, want) {
		t.Fatalf("resource order = %v, want %v", got, want)
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
