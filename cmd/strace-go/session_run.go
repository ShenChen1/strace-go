package main

import (
	"errors"
	"fmt"
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
const traceEventBatchLimit = 64

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
	RefreshAttachTargets() error
}

type traceCommandLifecycleReader interface {
	TargetLifecycleExited(pid uint32) (bool, error)
	TargetLifecycleEventObserved(pid uint32) bool
	TargetLifecycleQuiescent(pid uint32) bool
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
	commandExited            bool
	commandLifecycleDone     bool
	commandLifecycleObserved bool
	commandLifecycleFallback bool
	command                  traceCommandWaiter
	cmdDone                  <-chan struct{}
	targetPID                uint32
	commandLifecycle         traceCommandLifecycleReader
	attachExited             bool
	attachPids               []int
	attachState              traceAttachStateReader
	fallbackFlush            time.Time
	lifecycleFallbackAt      time.Time
	clock                    traceClock
}

type traceRunStateDeps struct {
	command          traceCommandWaiter
	commandLifecycle traceCommandLifecycleReader
	targetPID        uint32
	attachPids       []int
	attachState      traceAttachStateReader
	clock            traceClock
}

type traceCommandExitResult struct {
	exited   bool
	exitCode uint64
}

// IMPACT: run reads and handles ringbuf records in the same goroutine; only process waiting is asynchronous.
func (s *traceSession) run() error {
	s.emitDebugPhase("trace_start")
	deps := s.dependencies
	state := newTraceRunState(traceRunStateDeps{
		command:          deps.CommandWaiter,
		commandLifecycle: deps.State,
		targetPID:        traceTargetPIDValue(deps.TargetPID),
		attachPids:       s.sessionAttachPIDs(),
		attachState:      deps.State,
		clock:            deps.Clock,
	})
	commandExit := s.commandExitHandler()
	eventReader := s.traceEventReader()
	var rec ringbuf.Record

	for {
		fallbackBefore := state.commandLifecycleFallback
		if err := state.collect(commandExit); err != nil {
			return errors.Join(err, s.finishRun())
		}
		if !fallbackBefore && state.commandLifecycleFallback {
			s.emitDebugPhase("lifecycle_fallback")
		}
		if state.done() {
			return errors.Join(eventReader.DrainAfterDone(&rec, s.exitDrainGraceForState(state)), s.finishRun())
		}
		status, err := readTraceEventBatch(
			eventReader,
			&rec,
			traceEventPollInterval,
			traceEventBatchLimit,
		)
		if err != nil {
			return errors.Join(err, s.finishRun())
		}
		if status == traceReadClosed {
			return s.finishRun()
		}
	}
}

func readTraceEventBatch(
	reader *TraceEventReader,
	rec *ringbuf.Record,
	timeout time.Duration,
	limit int,
) (traceReadStatus, error) {
	if reader == nil {
		return traceReadNoEvent, nil
	}
	if limit < 1 {
		limit = 1
	}
	status, err := reader.Read(rec, timeout)
	if err != nil || status != traceReadHandled {
		return status, err
	}
	for count := 1; count < limit && rec != nil && rec.Remaining > 0; count++ {
		status, err = reader.Read(rec, timeout)
		if err != nil || status != traceReadHandled {
			return status, err
		}
	}
	return traceReadHandled, nil
}

func (s *traceSession) sessionAttachPIDs() []int {
	if s == nil || s.components == nil || s.dependencies.OutputPolicy == nil {
		return nil
	}
	return s.dependencies.OutputPolicy.AttachPIDs()
}

func newTraceRunState(deps traceRunStateDeps) traceRunState {
	commandExited := deps.command == nil
	state := traceRunState{
		commandExited:        commandExited,
		commandLifecycleDone: commandExited || deps.targetPID == 0 || deps.commandLifecycle == nil,
		command:              deps.command,
		targetPID:            deps.targetPID,
		commandLifecycle:     deps.commandLifecycle,
		attachExited:         len(deps.attachPids) == 0,
		clock:                deps.clock,
		attachState:          deps.attachState,
	}
	if !state.commandExited {
		state.cmdDone = deps.command.Done()
	}
	state.attachPids = append([]int(nil), deps.attachPids...)
	return state
}

func (st *traceRunState) collect(commandExit *TraceCommandExitHandler) error {
	if st == nil || st.clock == nil || (len(st.attachPids) > 0 && st.attachState == nil) {
		return nil
	}
	now := st.now()
	if st.cmdDone != nil {
		select {
		case <-st.cmdDone:
			result := st.command.Wait()
			commandExit.MarkExited(result)
			st.commandExited = true
			st.command = nil
			st.cmdDone = nil
			// IMPACT: print the wait-derived exit line shortly after wait
			// completes (once any lagging ringbuf exit event has been
			// processed) instead of waiting for the end-of-run drain, so
			// exit lines keep event-stream ordering.
			st.fallbackFlush = now.Add(traceExitFallbackGrace)
		default:
		}
	}
	if err := st.collectCommandLifecycle(); err != nil {
		return err
	}
	if st.commandExited && st.commandLifecycleDone && !st.fallbackFlush.IsZero() && now.After(st.fallbackFlush) {
		st.fallbackFlush = time.Time{}
		commandExit.FlushFallback()
	}
	if len(st.attachPids) == 0 {
		st.attachExited = true
		return nil
	}
	if st.attachExited {
		return nil
	}
	if err := st.attachState.RefreshAttachTargets(); err != nil {
		return fmt.Errorf("refresh attach targets: %w", err)
	}
	if st.attachState.AttachTargetsDone() {
		st.attachExited = true
	}
	return nil
}

func (st traceRunState) done() bool {
	if !st.commandExited || !st.commandLifecycleDone || !st.attachExited {
		return false
	}
	if st.commandLifecycleFallback {
		return true
	}
	if !st.commandLifecycleObserved {
		return true
	}
	if st.commandLifecycle == nil {
		return false
	}
	return st.commandLifecycle.TargetLifecycleQuiescent(st.targetPID)
}

func (st *traceRunState) collectCommandLifecycle() error {
	if st == nil || !st.commandExited ||
		st.targetPID == 0 || st.commandLifecycle == nil {
		return nil
	}
	if st.commandLifecycleFallback {
		return nil
	}
	if st.commandLifecycleObserved {
		st.collectLifecycleQuiescence()
		return nil
	}
	if st.commandLifecycleDone {
		return nil
	}
	if st.commandLifecycle.TargetLifecycleEventObserved(st.targetPID) {
		st.commandLifecycleDone = true
		st.commandLifecycleObserved = true
		st.commandLifecycleFallback = false
		st.lifecycleFallbackAt = time.Time{}
		st.collectLifecycleQuiescence()
		return nil
	}
	exited, err := st.commandLifecycle.TargetLifecycleExited(st.targetPID)
	if err != nil {
		return fmt.Errorf("refresh command lifecycle: %w", err)
	}
	if !exited {
		return nil
	}
	now := st.now()
	if st.lifecycleFallbackAt.IsZero() {
		st.lifecycleFallbackAt = now.Add(traceExitLifecycleDrainGrace)
		return nil
	}
	if !now.Before(st.lifecycleFallbackAt) {
		st.commandLifecycleDone = true
		st.commandLifecycleFallback = true
	}
	return nil
}

func (st *traceRunState) collectLifecycleQuiescence() {
	if st.commandLifecycle.TargetLifecycleQuiescent(st.targetPID) {
		st.lifecycleFallbackAt = time.Time{}
		return
	}
	now := st.now()
	if st.lifecycleFallbackAt.IsZero() {
		st.lifecycleFallbackAt = now.Add(traceExitLifecycleDrainGrace)
		return
	}
	if !now.Before(st.lifecycleFallbackAt) {
		st.commandLifecycleFallback = true
	}
}

func traceTargetPIDValue(pid int) uint32 {
	if pid <= 0 {
		return 0
	}
	return uint32(pid)
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

func (s *traceSession) exitDrainGraceForState(state traceRunState) time.Duration {
	if state.commandLifecycleFallback {
		return traceExitLifecycleDrainGrace
	}
	if state.commandLifecycleObserved {
		return 0
	}
	return s.exitDrainGrace()
}

func (s *traceSession) finishRun() error {
	s.emitDebugPhase("trace_end")
	s.emitDebugPhase("finalize_start")
	return s.traceRunFinalizer().Finish()
}
