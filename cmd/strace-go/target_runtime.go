package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// traceCommandWaiter exposes the completed command result without exposing
// exec.Cmd ownership to the event loop.
type traceCommandWaiter interface {
	Wait() traceCommandExitResult
	Done() <-chan struct{}
}

type traceCommandCompletion struct {
	command *exec.Cmd
	done    chan struct{}
	result  traceCommandExitResult
}

// traceTargetRuntime is the sole owner of a started tracee command's Wait.
// The result is published through channel close so readers need no mutex.
type traceTargetRuntime struct {
	command        *exec.Cmd
	completion     *traceCommandCompletion
	abortRequested bool
}

func newTraceTargetRuntime(command *exec.Cmd) *traceTargetRuntime {
	if command == nil {
		return nil
	}
	completion := &traceCommandCompletion{
		command: command,
		done:    make(chan struct{}),
	}
	runtime := &traceTargetRuntime{command: command, completion: completion}
	go completion.wait()
	return runtime
}

func (c *traceCommandCompletion) wait() {
	err := c.command.Wait()
	c.result = newTraceCommandExitResult(c.command.ProcessState, err)
	close(c.done)
}

func (c *traceCommandCompletion) Wait() traceCommandExitResult {
	if c == nil {
		return traceCommandExitResult{}
	}
	<-c.done
	return c.result
}

func (c *traceCommandCompletion) Done() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.done
}

func (r *traceTargetRuntime) commandWaiter() traceCommandWaiter {
	if r == nil {
		return nil
	}
	return r.completion
}

// Abort requests termination and waits for the already-owned completion.
// Repeated calls are harmless and never call exec.Cmd.Wait a second time.
func (r *traceTargetRuntime) Abort() error {
	if r == nil || r.abortRequested {
		return nil
	}
	r.abortRequested = true
	var abortErr error
	if r.command != nil && r.command.Process != nil {
		if err := r.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			abortErr = fmt.Errorf("kill tracee: %w", err)
		}
	}
	if r.completion != nil {
		_ = r.completion.Wait()
	}
	return abortErr
}

var _ traceCommandWaiter = (*traceCommandCompletion)(nil)
