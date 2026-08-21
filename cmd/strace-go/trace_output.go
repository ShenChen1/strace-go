package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

const traceOutputBufferSize = 64 * 1024

type traceOutputWaiter interface {
	Wait() error
}

type execTraceOutputWaiter struct {
	command *exec.Cmd
}

func (w execTraceOutputWaiter) Wait() error {
	return w.command.Wait()
}

// TraceOutput owns the writer and the optional process behind an output pipe.
// The session finalizer is its single close owner; Close is intentionally not
// synchronized because it is outside the event state machine.
type TraceOutput struct {
	writer   io.Writer
	closer   io.Closer
	command  traceOutputWaiter
	flushFn  func() error
	closed   bool
	writeErr error
	flushErr error
	closeErr error
}

type TraceOutputDeps struct {
	Writer  io.Writer
	Closer  io.Closer
	Command traceOutputWaiter
	Flush   func() error
}

// traceOutputHandoff owns a bootstrap-created output until session composition
// succeeds. After transfer, the session finalizer becomes the sole close owner.
type traceOutputHandoff struct {
	output *TraceOutput
	owned  bool
}

func newTraceOutputHandoff(output *TraceOutput) (*traceOutputHandoff, error) {
	if output == nil {
		return nil, fmt.Errorf("trace output handoff is nil")
	}
	return &traceOutputHandoff{output: output, owned: true}, nil
}

func (h *traceOutputHandoff) Output() *TraceOutput {
	if h == nil {
		return nil
	}
	return h.output
}

func (h *traceOutputHandoff) Transfer() error {
	if h == nil || h.output == nil {
		return fmt.Errorf("trace output handoff is unavailable")
	}
	if !h.owned {
		return fmt.Errorf("trace output ownership already transferred")
	}
	h.owned = false
	return nil
}

func (h *traceOutputHandoff) Close() error {
	if h == nil || !h.owned || h.output == nil {
		return nil
	}
	h.owned = false
	return h.output.Close()
}

func newTraceOutput(deps TraceOutputDeps) (*TraceOutput, error) {
	if deps.Writer == nil {
		return nil, fmt.Errorf("trace output writer is nil")
	}
	return &TraceOutput{
		writer:  deps.Writer,
		closer:  deps.Closer,
		command: deps.Command,
		flushFn: deps.Flush,
	}, nil
}

// EnableBuffer batches output at the ownership boundary without adding an
// asynchronous writer to the event pipeline.
func (o *TraceOutput) EnableBuffer(size int) error {
	if o == nil || o.writer == nil {
		return fmt.Errorf("trace output is unavailable")
	}
	if o.closed {
		return fmt.Errorf("trace output is closed")
	}
	if size < 1 {
		return fmt.Errorf("trace output buffer size must be positive")
	}
	if o.flushFn != nil {
		return nil
	}
	buffered := bufio.NewWriterSize(o.writer, size)
	o.writer = buffered
	o.flushFn = buffered.Flush
	return nil
}

func (o *TraceOutput) Write(p []byte) (int, error) {
	if o == nil || o.writer == nil {
		return 0, fmt.Errorf("trace output is unavailable")
	}
	if o.closed {
		return 0, fmt.Errorf("trace output is closed")
	}
	n, err := o.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil && o.writeErr == nil {
		o.writeErr = fmt.Errorf("write trace output: %w", err)
	}
	return n, err
}

// WriteBatch writes a large synchronous batch after draining the optional
// bufio layer, so the batch can cross the underlying writer boundary intact.
func (o *TraceOutput) WriteBatch(p []byte) (int, error) {
	if o == nil || o.writer == nil {
		return 0, fmt.Errorf("trace output is unavailable")
	}
	if o.closed {
		return 0, fmt.Errorf("trace output is closed")
	}
	if o.flushFn != nil {
		if err := o.Flush(); err != nil {
			return 0, err
		}
	}
	n, err := o.Write(p)
	if o.flushFn != nil {
		flushErr := o.Flush()
		if err == nil {
			err = flushErr
		}
	}
	return n, err
}

func (o *TraceOutput) Flush() error {
	if o == nil || o.flushFn == nil {
		return nil
	}
	if o.closed {
		return fmt.Errorf("trace output is closed")
	}
	if o.flushErr != nil {
		return o.flushErr
	}
	if err := o.flushFn(); err != nil {
		o.flushErr = fmt.Errorf("flush trace output: %w", err)
		return o.flushErr
	}
	return nil
}

func (o *TraceOutput) Close() error {
	if o == nil {
		return nil
	}
	if o.closed {
		return o.closeErr
	}
	flushErr := o.Flush()
	o.closed = true

	closeErr := o.writeErr
	closeErr = errors.Join(closeErr, flushErr)
	if o.closer != nil {
		closeErr = errors.Join(closeErr, o.closer.Close())
	}
	if o.command != nil {
		closeErr = errors.Join(closeErr, o.command.Wait())
	}
	o.closeErr = closeErr
	return closeErr
}
