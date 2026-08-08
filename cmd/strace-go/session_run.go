package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"strace-go/pkg/cli"
)

const traceEventPollInterval = 100 * time.Millisecond
const traceExitLifecycleDrainGrace = 200 * time.Millisecond
const traceExitDrainPollInterval = 10 * time.Millisecond
const traceExitFallbackGrace = 100 * time.Millisecond

type traceReadStatus uint8

const (
	traceReadHandled traceReadStatus = iota
	traceReadNoEvent
	traceReadClosed
)

type traceRunState struct {
	commandExited  bool
	cmdDone        <-chan traceCommandExitResult
	attachExited   bool
	attachPids     []int
	nextAttachPoll time.Time
	fallbackFlush  time.Time
}

type traceRunStateDeps struct {
	command    *exec.Cmd
	attachPids []int
}

type traceCommandExitResult struct {
	exited   bool
	exitCode uint64
}

// IMPACT: run reads and handles ringbuf records in the same goroutine; only process waiting is asynchronous.
func (s *traceSession) run() {
	attachPids := []int(nil)
	if s.opts != nil {
		attachPids = s.opts.AttachPids
	}
	state := newTraceRunState(traceRunStateDeps{
		command:    s.cmd,
		attachPids: attachPids,
	})
	commandExit := s.commandExitHandler()
	eventReader := s.traceEventReader()
	var rec ringbuf.Record

	for {
		state.collect(commandExit)
		if state.done() {
			eventReader.DrainAfterDone(&rec, s.exitDrainGrace())
			s.finishRun()
			return
		}
		if eventReader.Read(&rec, traceEventPollInterval) == traceReadClosed {
			s.finishRun()
			return
		}
	}
}

func newTraceRunState(deps traceRunStateDeps) traceRunState {
	state := traceRunState{
		commandExited: deps.command == nil,
		attachExited:  len(deps.attachPids) == 0,
	}
	if !state.commandExited {
		ch := make(chan traceCommandExitResult, 1)
		state.cmdDone = ch
		command := deps.command
		go func() {
			err := command.Wait()
			ch <- newTraceCommandExitResult(command.ProcessState, err)
		}()
	}
	state.attachPids = append([]int(nil), deps.attachPids...)
	return state
}

func (st *traceRunState) collect(commandExit *TraceCommandExitHandler) {
	if st.cmdDone != nil {
		select {
		case result := <-st.cmdDone:
			commandExit.MarkExited(result)
			st.commandExited = true
			st.cmdDone = nil
			// IMPACT: print the wait-derived exit line shortly after wait
			// completes (once any lagging ringbuf exit event has been
			// processed) instead of waiting for the end-of-run drain, so
			// exit lines keep event-stream ordering.
			st.fallbackFlush = time.Now().Add(traceExitFallbackGrace)
		default:
		}
	}
	if st.commandExited && !st.fallbackFlush.IsZero() && time.Now().After(st.fallbackFlush) {
		st.fallbackFlush = time.Time{}
		commandExit.FlushFallback()
	}
	if st.attachExited || !st.shouldPollAttach() {
		return
	}
	if !anyAttachPidAlive(st.attachPids) {
		st.attachExited = true
	}
}

func (st traceRunState) done() bool {
	return st.commandExited && st.attachExited
}

func newTraceCommandExitResult(state *os.ProcessState, waitErr error) traceCommandExitResult {
	if waitErr == nil {
		return traceCommandExitResult{exited: true}
	}
	if state == nil {
		return traceCommandExitResult{}
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Exited() {
		return traceCommandExitResult{exited: true, exitCode: uint64(status.ExitStatus())}
	}
	if code := state.ExitCode(); code >= 0 {
		return traceCommandExitResult{exited: true, exitCode: uint64(code)}
	}
	return traceCommandExitResult{}
}

func (st *traceRunState) shouldPollAttach() bool {
	now := time.Now()
	if !st.nextAttachPoll.IsZero() && now.Before(st.nextAttachPoll) {
		return false
	}
	st.nextAttachPoll = now.Add(traceEventPollInterval)
	return true
}

func anyAttachPidAlive(pids []int) bool {
	for _, pid := range pids {
		err := syscall.Kill(pid, 0)
		if err == nil || errors.Is(err, syscall.EPERM) {
			return true
		}
	}
	return false
}

func (s *traceSession) exitDrainGrace() time.Duration {
	if s == nil || s.opts == nil || s.opts.EventFormat != cli.EventFormatJSON {
		return 0
	}
	return traceExitLifecycleDrainGrace
}

func (s *traceSession) finishRun() {
	s.traceRunFinalizer().Finish()
}
