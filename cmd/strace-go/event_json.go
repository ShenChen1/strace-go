package main

import (
	"encoding/json"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

const (
	bpfEventTypeEnter        uint16 = 1
	bpfEventTypeExit         uint16 = 2
	bpfEventTypeLifecycle    uint16 = 3
	bpfEventFlagGenericEnter uint32 = 1
	bpfEventFlagPayloadTLV   uint32 = 2
	bpfEventFlagTruncated    uint32 = 4
	bpfEventFlagExitFragment uint32 = 8
	lifecycleFork            uint32 = 1
	lifecycleExec            uint32 = 2
	lifecycleExit            uint32 = 3
	lifecycleFree            uint32 = 4
)

type jsonSyscallEvent struct {
	Type            string               `json:"type"`
	EventVersion    uint16               `json:"event_version,omitempty"`
	EventType       string               `json:"event_type"`
	EventTypeID     uint16               `json:"event_type_id,omitempty"`
	EventFlags      uint32               `json:"event_flags,omitempty"`
	Pid             uint32               `json:"pid"`
	Tid             uint32               `json:"tid"`
	SysID           uint32               `json:"sys_id"`
	Syscall         string               `json:"syscall"`
	Args            [6]uint64            `json:"args"`
	ArgText         []string             `json:"arg_text,omitempty"`
	Ret             int64                `json:"ret"`
	ReturnText      string               `json:"return_text,omitempty"`
	Failed          bool                 `json:"failed"`
	Errno           int                  `json:"errno,omitempty"`
	DurationNS      uint64               `json:"duration_ns"`
	EnterTimeNS     uint64               `json:"enter_time_ns"`
	PayloadSections []jsonPayloadSection `json:"payload_sections,omitempty"`
	ProbeRetEnter   int32                `json:"probe_ret_enter"`
	ProbeRetExit    int32                `json:"probe_ret_exit"`
	PairedEnter     bool                 `json:"paired_enter,omitempty"`
}

type jsonPayloadSection struct {
	Kind       string `json:"kind"`
	Direction  string `json:"direction"`
	ArgIndex   int    `json:"arg_index"`
	UserPtr    uint64 `json:"user_ptr,omitempty"`
	UserLen    uint32 `json:"user_len,omitempty"`
	CopiedLen  uint32 `json:"copied_len"`
	ProbeRet   int32  `json:"probe_ret"`
	DataBase64 string `json:"data_base64,omitempty"`
}

type jsonLifecycleEvent struct {
	Type         string `json:"type"`
	EventVersion uint16 `json:"event_version,omitempty"`
	EventType    string `json:"event_type"`
	EventTypeID  uint16 `json:"event_type_id,omitempty"`
	EventFlags   uint32 `json:"event_flags,omitempty"`
	Action       string `json:"action"`
	ActionID     uint32 `json:"action_id,omitempty"`
	Pid          uint32 `json:"pid"`
	Tid          uint32 `json:"tid"`
	TaskTID      uint32 `json:"task_tid,omitempty"`
	TaskTGID     uint32 `json:"task_tgid,omitempty"`
	ParentTID    uint32 `json:"parent_tid,omitempty"`
	Alive        bool   `json:"alive"`
	Execed       bool   `json:"execed,omitempty"`
	Filename     string `json:"filename,omitempty"`
	Arg0         uint64 `json:"arg0,omitempty"`
	Arg1         uint64 `json:"arg1,omitempty"`
	TimeNS       uint64 `json:"time_ns"`
}

type jsonStatsEvent struct {
	Type                   string `json:"type"`
	RingbufReserveFail     uint64 `json:"ringbuf_reserve_fail"`
	RingbufCopyFail        uint64 `json:"ringbuf_copy_fail"`
	PayloadTruncatedEvents uint64 `json:"payload_truncated_events"`
	Available              bool   `json:"available"`
	Error                  string `json:"error,omitempty"`
}

func newJSONSyscallEventFromView(view syscallEventView, scMeta meta.Syscall, sections []handler.PayloadSection) jsonSyscallEvent {
	failed, errno := syscallFailure(view.ret)
	return jsonSyscallEvent{
		Type:            "syscall",
		EventVersion:    view.eventVersion,
		EventType:       bpfEventTypeNameFromID(view.eventType),
		EventTypeID:     view.eventType,
		EventFlags:      view.eventFlags,
		Pid:             view.pid,
		Tid:             view.tid,
		SysID:           view.sysID,
		Syscall:         scMeta.Name,
		Args:            view.args,
		Ret:             view.ret,
		Failed:          failed,
		Errno:           errno,
		DurationNS:      view.duration,
		EnterTimeNS:     view.enterTime,
		PayloadSections: jsonPayloadSections(sections),
		ProbeRetEnter:   view.probeRetEnter,
		ProbeRetExit:    view.probeRetExit,
	}
}

func syscallFailure(ret int64) (bool, int) {
	if ret < 0 && ret >= -4095 {
		return true, int(-ret)
	}
	return false, 0
}

func (s *traceSession) writeJSONRawEvent(ev syscallEventContext) {
	jsonEvent := ev.newJSONRawSyscallEvent()
	_ = json.NewEncoder(s.outWriter).Encode(jsonEvent)
}

func (s *traceSession) writeJSONLifecycleEventView(view lifecycleEventView, task *TaskState) {
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
	_ = json.NewEncoder(s.outWriter).Encode(ev)
}

func newJSONStatsEvent(stats bpfRuntimeStats) jsonStatsEvent {
	return jsonStatsEvent{
		Type:                   "stats",
		RingbufReserveFail:     stats.RingbufReserveFail,
		RingbufCopyFail:        stats.RingbufCopyFail,
		PayloadTruncatedEvents: stats.PayloadTruncatedEvents,
		Available:              stats.Available,
		Error:                  stats.Error,
	}
}

func (s *traceSession) maybeWriteJSONStatsEvent() {
	if s == nil || s.opts == nil || s.opts.EventFormat != cli.EventFormatJSON {
		return
	}
	s.writeJSONStatsEvent(s.collectBPFStats())
}

func (s *traceSession) writeJSONStatsEvent(stats bpfRuntimeStats) {
	_ = json.NewEncoder(s.outWriter).Encode(newJSONStatsEvent(stats))
}

func (s *traceSession) writeJSONDecodedEvent(syscallEvent syscallEventContext, res handler.Result) {
	ev := syscallEvent.newJSONDecodedSyscallEvent(res)
	_ = json.NewEncoder(s.outWriter).Encode(ev)
}

func (ev syscallEventContext) newJSONRawSyscallEvent() jsonSyscallEvent {
	return ev.newJSONSyscallEvent(ev.outputPayloadSections())
}

func (ev syscallEventContext) newJSONDecodedSyscallEvent(res handler.Result) jsonSyscallEvent {
	jsonEvent := ev.newJSONSyscallEvent(ev.decodedPayloadSections())
	jsonEvent.ArgText = res.ArgParts
	jsonEvent.ReturnText = ev.returnText(res)
	jsonEvent.PairedEnter = ev.pairedGenericEnter()
	return jsonEvent
}

func (ev syscallEventContext) newJSONSyscallEvent(sections []handler.PayloadSection) jsonSyscallEvent {
	return newJSONSyscallEventFromView(ev.eventView(), ev.effectiveSyscallMeta(), sections)
}

func bpfEventTypeNameFromID(eventType uint16) string {
	switch eventType {
	case bpfEventTypeEnter:
		return "enter"
	case bpfEventTypeExit:
		return "exit"
	case bpfEventTypeLifecycle:
		return "lifecycle"
	default:
		return "unknown"
	}
}

func lifecycleActionName(action uint32) string {
	switch action {
	case lifecycleFork:
		return "fork"
	case lifecycleExec:
		return "exec"
	case lifecycleExit:
		return "exit"
	case lifecycleFree:
		return "free"
	default:
		return "unknown"
	}
}

type successfulFailedOptions struct {
	successfulOnly bool
	failedOnly     bool
	traceStatus    map[string]bool
}
