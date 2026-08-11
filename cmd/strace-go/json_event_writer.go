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

// JSONEventWriter is the only user-space JSON encoding boundary for event
// records. Filtering and event selection stay in the output policy objects.
type JSONEventWriter struct {
	encoder *json.Encoder
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
	w.encode(ev.newJSONRawSyscallEvent())
}

func (w *JSONEventWriter) WriteDecoded(ev syscallEventContext, res handler.Result) {
	w.encode(ev.newJSONDecodedSyscallEvent(res))
}

func (w *JSONEventWriter) WriteLifecycle(view lifecycleEventView, task *TaskState) {
	w.encode(newJSONLifecycleEvent(view, task))
}

func (w *JSONEventWriter) WriteReady(targetPID int, attachPIDs []int) {
	w.encode(newJSONReadyEvent(targetPID, attachPIDs))
}

func (w *JSONEventWriter) encode(event any) {
	if w == nil || w.encoder == nil {
		return
	}
	_ = w.encoder.Encode(event)
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
	}
	return ev
}

func (s *traceSession) jsonEventWriter() *JSONEventWriter {
	components := s.componentsOrBuild()
	if components == nil {
		return nil
	}
	return components.jsonWriter
}

func (s *traceSession) emitDebugReady() {
	if s == nil || s.opts == nil || !s.opts.DebugEvents {
		return
	}
	s.jsonEventWriter().WriteReady(s.targetPid, s.opts.AttachPids)
}
