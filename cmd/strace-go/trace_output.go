package main

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
)

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
	closed   bool
	closeErr error
}

type TraceOutputDeps struct {
	Writer  io.Writer
	Closer  io.Closer
	Command traceOutputWaiter
}

func newTraceOutput(deps TraceOutputDeps) (*TraceOutput, error) {
	if deps.Writer == nil {
		return nil, fmt.Errorf("trace output writer is nil")
	}
	return &TraceOutput{
		writer:  deps.Writer,
		closer:  deps.Closer,
		command: deps.Command,
	}, nil
}

func (o *TraceOutput) Write(p []byte) (int, error) {
	if o == nil || o.writer == nil {
		return 0, fmt.Errorf("trace output is unavailable")
	}
	if o.closed {
		return 0, fmt.Errorf("trace output is closed")
	}
	return o.writer.Write(p)
}

func (o *TraceOutput) Close() error {
	if o == nil {
		return nil
	}
	if o.closed {
		return o.closeErr
	}
	o.closed = true

	var closeErr error
	if o.closer != nil {
		closeErr = o.closer.Close()
	}
	if o.command != nil {
		closeErr = errors.Join(closeErr, o.command.Wait())
	}
	o.closeErr = closeErr
	return closeErr
}
