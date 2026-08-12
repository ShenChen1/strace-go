package main

import "os/exec"

// traceCommandWaiter exposes the completed command result without exposing
// exec.Cmd ownership to the event loop.
type traceCommandWaiter interface {
	Wait() traceCommandExitResult
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

func (r *traceTargetRuntime) commandWaiter() traceCommandWaiter {
	if r == nil {
		return nil
	}
	return r.completion
}

// Abort requests termination and waits for the already-owned completion.
// Repeated calls are harmless and never call exec.Cmd.Wait a second time.
func (r *traceTargetRuntime) Abort() {
	if r == nil || r.abortRequested {
		return
	}
	r.abortRequested = true
	if r.command != nil && r.command.Process != nil {
		_ = r.command.Process.Kill()
	}
	if r.completion != nil {
		_ = r.completion.Wait()
	}
}

var _ traceCommandWaiter = (*traceCommandCompletion)(nil)
