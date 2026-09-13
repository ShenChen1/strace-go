package main

import (
	"encoding/json"
	"io"

	"strace-go/pkg/handler"
)

type jsonEventWriter interface {
	WriteRaw(syscallEventContext)
	WriteDecoded(syscallEventContext, handler.Result)
	WriteLifecycle(lifecycleEventView, *TaskState)
}

// traceDebugPhasePort is the narrow phase capability used by bootstrap and
// finalization boundaries; it does not expose syscall event encoding.
type traceDebugPhasePort interface {
	EmitPhase(string)
	EmitPhaseAt(string, uint64, uint64)
}

type traceJSONOutputStats struct {
	SyscallBytesWritten     uint64
	SyscallWriteCalls       uint64
	SyscallWriteErrors      uint64
	SyscallWriteTimeNS      uint64
	SyscallWriteTimeSamples uint64
}

type traceJSONOutputStatsReader interface {
	JSONOutputStats() traceJSONOutputStats
}

type traceDebugPhaseWriter struct {
	policy traceReadyPolicy
	writer *JSONEventWriter
	clock  traceClock
}

func newTraceDebugPhaseWriter(
	policy traceReadyPolicy,
	writer *JSONEventWriter,
	clock traceClock,
) *traceDebugPhaseWriter {
	return &traceDebugPhaseWriter{policy: policy, writer: writer, clock: clock}
}

func (w *traceDebugPhaseWriter) EmitPhase(phase string) {
	var timeNS uint64
	if w != nil && w.clock != nil {
		timeNS = w.clock.NowMonoNs()
	}
	w.EmitPhaseAt(phase, 0, timeNS)
}

func (w *traceDebugPhaseWriter) EmitPhaseAt(phase string, startTimeNS, timeNS uint64) {
	if w == nil || w.policy == nil || !w.policy.DebugPhases() || w.writer == nil {
		return
	}
	w.writer.WritePhaseAt(phase, startTimeNS, timeNS)
}

// JSONEventWriter is the only user-space JSON encoding boundary for event
// records. Filtering and event selection stay in the output policy objects.
type JSONEventWriter struct {
	encoder             *json.Encoder
	out                 io.Writer
	flusher             interface{ Flush() error }
	batchWriter         interface{ WriteBatch([]byte) (int, error) }
	syscallBuffer       []byte
	syscallBytesWritten uint64
	syscallWriteCalls   uint64
	syscallWriteErrors  uint64
	syscallWriteTimeNS  uint64
	syscallWriteSamples uint64
	clock               traceClock
	measureSyscallWrite bool
	lifecycleEvent      jsonLifecycleEvent
}

const jsonSyscallBatchSize = traceOutputBufferSize + 1

type JSONEventWriterDeps struct {
	Out                  io.Writer
	Clock                traceClock
	MeasureSyscallWrites bool
}

func newJSONEventWriter(deps JSONEventWriterDeps) *JSONEventWriter {
	writer := &JSONEventWriter{
		clock:               deps.Clock,
		measureSyscallWrite: deps.MeasureSyscallWrites && deps.Clock != nil,
	}
	if deps.Out != nil {
		writer.out = deps.Out
		writer.encoder = json.NewEncoder(deps.Out)
		if flusher, ok := deps.Out.(interface{ Flush() error }); ok {
			writer.flusher = flusher
		}
		if batchWriter, ok := deps.Out.(interface{ WriteBatch([]byte) (int, error) }); ok {
			writer.batchWriter = batchWriter
		}
	}
	return writer
}

func (w *JSONEventWriter) Flush() error {
	if w == nil {
		return nil
	}
	if w.batchWriter != nil {
		w.flushSyscallBuffer()
	}
	if w.flusher == nil {
		return nil
	}
	return w.flusher.Flush()
}

func (w *JSONEventWriter) JSONOutputStats() traceJSONOutputStats {
	if w == nil {
		return traceJSONOutputStats{}
	}
	return traceJSONOutputStats{
		SyscallBytesWritten:     w.syscallBytesWritten,
		SyscallWriteCalls:       w.syscallWriteCalls,
		SyscallWriteErrors:      w.syscallWriteErrors,
		SyscallWriteTimeNS:      w.syscallWriteTimeNS,
		SyscallWriteTimeSamples: w.syscallWriteSamples,
	}
}

func (w *JSONEventWriter) WriteRaw(ev syscallEventContext) {
	if !w.canEncode() {
		return
	}
	if w.batchWriter == nil {
		w.syscallBuffer = appendJSONRawSyscallEvent(w.syscallBuffer[:0], ev)
		w.writeSyscallBuffer()
		return
	}
	w.syscallBuffer = appendJSONRawSyscallEvent(w.syscallBuffer, ev)
	w.flushSyscallBufferIfFull()
}

func (w *JSONEventWriter) WriteDecoded(ev syscallEventContext, res handler.Result) {
	if !w.canEncode() {
		return
	}
	if w.batchWriter == nil {
		w.syscallBuffer = appendJSONDecodedSyscallEvent(w.syscallBuffer[:0], ev, res)
		w.writeSyscallBuffer()
		return
	}
	w.syscallBuffer = appendJSONDecodedSyscallEvent(w.syscallBuffer, ev, res)
	w.flushSyscallBufferIfFull()
}

func (w *JSONEventWriter) WriteLifecycle(view lifecycleEventView, task *TaskState) {
	if !w.canEncode() {
		return
	}
	w.lifecycleEvent = newJSONLifecycleEvent(view, task)
	w.encode(&w.lifecycleEvent)
	w.lifecycleEvent = jsonLifecycleEvent{}
}

func (w *JSONEventWriter) WriteReadyAt(
	targetPID int,
	attachPIDs []int,
	startTimeNS uint64,
	timeNS uint64,
) {
	w.encode(newJSONReadyEventAt(targetPID, attachPIDs, startTimeNS, timeNS))
}

func (w *JSONEventWriter) WritePhase(phase string, timeNS uint64) {
	w.encode(newJSONPhaseEvent(phase, timeNS))
}

func (w *JSONEventWriter) WritePhaseAt(phase string, startTimeNS uint64, timeNS uint64) {
	w.encode(newJSONPhaseEventAt(phase, startTimeNS, timeNS))
}

func (w *JSONEventWriter) encode(event any) {
	if !w.canEncode() {
		return
	}
	if w.batchWriter != nil {
		w.flushSyscallBuffer()
	}
	_ = w.encoder.Encode(event)
}

func (w *JSONEventWriter) writeSyscallBuffer() {
	if w == nil || w.out == nil || len(w.syscallBuffer) == 0 {
		return
	}
	startNS, measured := w.beginSyscallWrite()
	n, err := w.out.Write(w.syscallBuffer)
	w.recordSyscallWrite(n, err)
	w.finishSyscallWrite(startNS, measured)
}

func (w *JSONEventWriter) flushSyscallBufferIfFull() {
	if w == nil || len(w.syscallBuffer) < jsonSyscallBatchSize {
		return
	}
	w.flushSyscallBuffer()
}

func (w *JSONEventWriter) flushSyscallBuffer() {
	if w == nil || w.out == nil || len(w.syscallBuffer) == 0 {
		return
	}
	if w.batchWriter != nil {
		startNS, measured := w.beginSyscallWrite()
		n, err := w.batchWriter.WriteBatch(w.syscallBuffer)
		w.recordSyscallWrite(n, err)
		w.finishSyscallWrite(startNS, measured)
	} else {
		startNS, measured := w.beginSyscallWrite()
		n, err := w.out.Write(w.syscallBuffer)
		w.recordSyscallWrite(n, err)
		w.finishSyscallWrite(startNS, measured)
	}
	w.syscallBuffer = w.syscallBuffer[:0]
}

func (w *JSONEventWriter) recordSyscallWrite(n int, err error) {
	if w == nil {
		return
	}
	w.syscallWriteCalls++
	if n > 0 {
		w.syscallBytesWritten += uint64(n)
	}
	if err != nil {
		w.syscallWriteErrors++
	}
}

func (w *JSONEventWriter) beginSyscallWrite() (uint64, bool) {
	if w == nil || !w.measureSyscallWrite || w.clock == nil {
		return 0, false
	}
	return w.clock.NowMonoNs(), true
}

func (w *JSONEventWriter) finishSyscallWrite(startNS uint64, measured bool) {
	if w == nil || !measured || w.clock == nil {
		return
	}
	endNS := w.clock.NowMonoNs()
	if endNS < startNS {
		return
	}
	w.syscallWriteSamples++
	w.syscallWriteTimeNS += endNS - startNS
}

func (w *JSONEventWriter) canEncode() bool {
	return w != nil && w.encoder != nil
}

func newJSONLifecycleEvent(view lifecycleEventView, task *TaskState) jsonLifecycleEvent {
	ev := jsonLifecycleEvent{
		traceRecordIntegrity: view.integrity,
		Type:                 "lifecycle",
		EventVersion:         view.eventVersion,
		EventType:            bpfEventTypeNameFromID(view.eventType),
		EventTypeID:          view.eventType,
		EventFlags:           view.eventFlags,
		Action:               lifecycleActionName(view.action),
		ActionID:             view.action,
		Pid:                  view.pid,
		Tid:                  view.tid,
		Arg0:                 view.args[0],
		Arg1:                 view.args[1],
		TimeNS:               view.enterTime,
	}
	if view.action == lifecycleExec {
		ev.Filename = view.snapshotText
	}
	if task != nil {
		ev.TaskTID = task.TID
		ev.TaskTGID = task.TGID
		ev.ParentTID = task.ParentTID
		ev.Alive = task.Alive
		ev.Execed = task.Execed
		ev.TaskExecutable = task.Executable
	}
	return ev
}

func (s *traceSession) jsonEventWriter() *JSONEventWriter {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.jsonWriter
}

func (s *traceSession) emitDebugReady() {
	s.emitDebugReadyAt(0)
}

func (s *traceSession) emitDebugReadyAt(startTimeNS uint64) {
	if s == nil || s.components == nil || s.dependencies.OutputPolicy == nil {
		return
	}
	var policy traceReadyPolicy = s.dependencies.OutputPolicy
	if !policy.DebugEvents() && !policy.DebugPhases() {
		return
	}
	if writer := s.jsonEventWriter(); writer != nil {
		writer.WriteReadyAt(
			s.dependencies.TargetPID,
			policy.AttachPIDs(),
			startTimeNS,
			s.debugTimeNS(),
		)
		_ = writer.Flush()
	}
}

func (s *traceSession) emitDebugPhase(phase string) {
	s.emitDebugPhaseAt(phase, 0, s.debugTimeNS())
}

func (s *traceSession) emitDebugPhaseAt(phase string, startTimeNS uint64, timeNS uint64) {
	if s == nil || s.components == nil || s.dependencies.OutputPolicy == nil {
		return
	}
	if !s.dependencies.OutputPolicy.DebugPhases() {
		return
	}
	if writer := s.components.debugPhases; writer != nil {
		writer.EmitPhaseAt(phase, startTimeNS, timeNS)
	}
}

func (s *traceSession) emitDebugBPFSetupPhases(timings []traceBPFSetupTiming) {
	if s == nil || s.dependencies.OutputPolicy == nil || !s.dependencies.OutputPolicy.DebugPhases() {
		return
	}
	for _, timing := range timings {
		s.emitDebugPhaseAt(string(timing.Stage), timing.StartNS, timing.EndNS)
	}
}

func (s *traceSession) debugTimeNS() uint64 {
	if s == nil || s.dependencies.Clock == nil {
		return 0
	}
	return s.dependencies.Clock.NowMonoNs()
}
