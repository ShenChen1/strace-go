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
	encoder         *json.Encoder
	syscallEvent    jsonSyscallEvent
	payloadSections []jsonPayloadSection
	lifecycleEvent  jsonLifecycleEvent
}

type JSONEventWriterDeps struct {
	Out io.Writer
}

func newJSONEventWriter(deps JSONEventWriterDeps) *JSONEventWriter {
	writer := &JSONEventWriter{}
	if deps.Out != nil {
		writer.encoder = json.NewEncoder(deps.Out)
	}
	return writer
}

func (w *JSONEventWriter) WriteRaw(ev syscallEventContext) {
	if !w.canEncode() {
		return
	}
	w.syscallEvent = ev.newJSONRawSyscallEventWithPayloadStorage(w.payloadSections)
	w.encode(&w.syscallEvent)
	w.recycleSyscallEvent()
}

func (w *JSONEventWriter) WriteDecoded(ev syscallEventContext, res handler.Result) {
	if !w.canEncode() {
		return
	}
	w.syscallEvent = ev.newJSONDecodedSyscallEventWithPayloadStorage(res, w.payloadSections)
	w.encode(&w.syscallEvent)
	w.recycleSyscallEvent()
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
	_ = w.encoder.Encode(event)
}

func (w *JSONEventWriter) canEncode() bool {
	return w != nil && w.encoder != nil
}

func (w *JSONEventWriter) recycleSyscallEvent() {
	if w == nil {
		return
	}
	payloadSections := w.syscallEvent.PayloadSections
	if payloadSections != nil {
		clear(payloadSections)
		w.payloadSections = payloadSections[:0]
	}
	w.syscallEvent = jsonSyscallEvent{}
}

func newJSONLifecycleEvent(view lifecycleEventView, task *TaskState) jsonLifecycleEvent {
	ev := jsonLifecycleEvent{
		Type:         "lifecycle",
		EventVersion: view.eventVersion,
		EventType:    bpfEventTypeNameFromID(view.eventType),
		EventTypeID:  view.eventType,
		EventFlags:   view.eventFlags,
		Action:       lifecycleActionName(view.action),
		ActionID:     view.action,
		Pid:          view.pid,
		Tid:          view.tid,
		Arg0:         view.args[0],
		Arg1:         view.args[1],
		TimeNS:       view.enterTime,
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
