package main

import (
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
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

type traceClock interface {
	Now() time.Time
	NowMonoNs() uint64
}

type traceAttachStateReader interface {
	AttachTargetsDone() bool
}

type systemTraceClock struct{}

func (systemTraceClock) Now() time.Time {
	return time.Now()
}

func (systemTraceClock) NowMonoNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

type traceRunState struct {
	commandExited bool
	cmdDone       <-chan traceCommandExitResult
	attachExited  bool
	attachPids    []int
	attachState   traceAttachStateReader
	fallbackFlush time.Time
	clock         traceClock
}

type traceRunStateDeps struct {
	command     traceCommandWaiter
	attachPids  []int
	attachState traceAttachStateReader
	clock       traceClock
}

type traceCommandExitResult struct {
	exited   bool
	exitCode uint64
}

// IMPACT: run reads and handles ringbuf records in the same goroutine; only process waiting is asynchronous.
func (s *traceSession) run() error {
	deps := s.dependencies
	state := newTraceRunState(traceRunStateDeps{
		command:     deps.CommandWaiter,
		attachPids:  s.sessionAttachPIDs(),
		attachState: deps.State,
		clock:       deps.Clock,
	})
	commandExit := s.commandExitHandler()
	eventReader := s.traceEventReader()
	var rec ringbuf.Record

	for {
		state.collect(commandExit)
		if state.done() {
			return errors.Join(eventReader.DrainAfterDone(&rec, s.exitDrainGrace()), s.finishRun())
		}
		status, err := eventReader.Read(&rec, traceEventPollInterval)
		if err != nil {
			return errors.Join(err, s.finishRun())
		}
		if status == traceReadClosed {
			return s.finishRun()
		}
	}
}

func (s *traceSession) sessionAttachPIDs() []int {
	if s == nil || s.components == nil || s.dependencies.OutputPolicy == nil {
		return nil
	}
	return s.dependencies.OutputPolicy.AttachPIDs()
}

func newTraceRunState(deps traceRunStateDeps) traceRunState {
	state := traceRunState{
		commandExited: deps.command == nil,
		attachExited:  len(deps.attachPids) == 0,
		clock:         deps.clock,
		attachState:   deps.attachState,
	}
	if !state.commandExited {
		ch := make(chan traceCommandExitResult, 1)
		state.cmdDone = ch
		command := deps.command
		go func() {
			ch <- command.Wait()
		}()
	}
	state.attachPids = append([]int(nil), deps.attachPids...)
	return state
}

func (st *traceRunState) collect(commandExit *TraceCommandExitHandler) {
	if st == nil || st.clock == nil || (len(st.attachPids) > 0 && st.attachState == nil) {
		return
	}
	now := st.now()
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
			st.fallbackFlush = now.Add(traceExitFallbackGrace)
		default:
		}
	}
	if st.commandExited && !st.fallbackFlush.IsZero() && now.After(st.fallbackFlush) {
		st.fallbackFlush = time.Time{}
		commandExit.FlushFallback()
	}
	if len(st.attachPids) == 0 {
		st.attachExited = true
		return
	}
	if st.attachExited {
		return
	}
	if st.attachState.AttachTargetsDone() {
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

func (st *traceRunState) now() time.Time {
	if st != nil && st.clock != nil {
		return st.clock.Now()
	}
	return time.Time{}
}

func (s *traceSession) exitDrainGrace() time.Duration {
	if s == nil || s.components == nil || s.dependencies.OutputPolicy == nil || !s.dependencies.OutputPolicy.IsJSON() {
		return 0
	}
	return traceExitLifecycleDrainGrace
}

func (s *traceSession) finishRun() error {
	return s.traceRunFinalizer().Finish()
}
