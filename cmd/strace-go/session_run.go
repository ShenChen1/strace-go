package main

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"strace-go/pkg/cli"
)

const traceEventPollInterval = 100 * time.Millisecond
const traceExitLifecycleDrainGrace = 200 * time.Millisecond
const traceExitDrainPollInterval = 10 * time.Millisecond

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
}

type traceCommandExitResult struct {
	exited   bool
	exitCode uint64
}

// IMPACT: run reads and handles ringbuf records in the same goroutine; only process waiting is asynchronous.
func (s *traceSession) run() {
	state := newTraceRunState(s)
	var rec ringbuf.Record

	for {
		state.collect(s)
		if state.done() {
			s.drainEventReaderAfterDone(&rec)
			s.finishRun()
			return
		}
		if s.readAndHandleEvent(&rec, traceEventPollInterval) == traceReadClosed {
			s.finishRun()
			return
		}
	}
}

func newTraceRunState(s *traceSession) traceRunState {
	state := traceRunState{
		commandExited: s.cmd == nil,
		attachExited:  s.opts == nil || len(s.opts.AttachPids) == 0,
	}
	if !state.commandExited {
		ch := make(chan traceCommandExitResult, 1)
		state.cmdDone = ch
		go func() {
			err := s.cmd.Wait()
			ch <- newTraceCommandExitResult(s.cmd.ProcessState, err)
		}()
	}
	if !state.attachExited {
		state.attachPids = append([]int(nil), s.opts.AttachPids...)
	}
	return state
}

func (st *traceRunState) collect(s *traceSession) {
	if st.cmdDone != nil {
		select {
		case result := <-st.cmdDone:
			s.exitStatusCoordinator().MarkExitedWithFallback(s.targetPid, s.commandExitFallbackLine(result))
			st.commandExited = true
			st.cmdDone = nil
		default:
		}
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

func (s *traceSession) commandExitFallbackLine(result traceCommandExitResult) string {
	if !result.exited || s == nil || s.opts == nil {
		return ""
	}
	if s.opts.QuietExit || s.opts.SummaryOnly || s.opts.EventFormat == cli.EventFormatJSON {
		return ""
	}
	return s.textRenderer().ExitStatusLine(s.targetPid, result.exitCode)
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

func (s *traceSession) readAndHandleEvent(rec *ringbuf.Record, timeout time.Duration) traceReadStatus {
	if s.events == nil {
		return traceReadClosed
	}
	s.events.SetDeadline(time.Now().Add(timeout))
	if err := s.events.ReadInto(rec); err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return traceReadClosed
		}
		if isTransientRingbufReadError(err) {
			return traceReadNoEvent
		}
		return traceReadNoEvent
	}
	if s.handleBPFRecord(rec) {
		return traceReadHandled
	}
	return traceReadNoEvent
}

func (s *traceSession) drainEventReader(rec *ringbuf.Record) {
	if s.events == nil {
		return
	}
	if err := s.events.Flush(); err != nil {
		return
	}
	s.events.SetDeadline(time.Time{})
	for {
		if err := s.events.ReadInto(rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || isTransientRingbufReadError(err) {
				return
			}
			return
		}
		s.handleBPFRecord(rec)
	}
}

func (s *traceSession) drainEventReaderAfterDone(rec *ringbuf.Record) {
	grace := s.exitDrainGrace()
	if grace <= 0 {
		s.drainEventReader(rec)
		return
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if s.readAndHandleEvent(rec, traceExitDrainPollInterval) == traceReadClosed {
			return
		}
	}
	s.drainEventReader(rec)
}

func (s *traceSession) exitDrainGrace() time.Duration {
	if s == nil || s.opts == nil || s.opts.EventFormat != cli.EventFormatJSON {
		return 0
	}
	return traceExitLifecycleDrainGrace
}

func (s *traceSession) handleBPFRecord(rec *ringbuf.Record) bool {
	ev, ok := decodeBPFEventRecord(rec.RawSample)
	if !ok {
		return false
	}
	s.handleEvent(&ev)
	return true
}

func decodeBPFEventRecord(rawSample []byte) (bpfEvent, bool) {
	var ev bpfEvent
	minSize := int(unsafe.Offsetof(ev.StrArg))
	if len(rawSample) < minSize {
		return ev, false
	}
	eventBytes := unsafe.Slice((*byte)(unsafe.Pointer(&ev)), int(unsafe.Sizeof(ev)))
	copy(eventBytes, rawSample)
	return ev, true
}

func isTransientRingbufReadError(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ringbuf.ErrFlushed)
}

func (s *traceSession) finishRun() {
	s.exitStatusCoordinator().FlushFallback(s.targetPid)
	s.maybeWriteJSONStatsEvent()
	if s.opts != nil && (s.opts.SummaryOnly || s.opts.SummaryAndPrint) {
		s.summaryStats().Print(s.outWriter)
	}
	if s.outPipe != nil {
		_ = s.outPipe.Close()
		if s.outCmd != nil {
			_ = s.outCmd.Wait()
		}
	}
}
