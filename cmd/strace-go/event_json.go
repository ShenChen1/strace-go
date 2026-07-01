package main

import (
	"bytes"
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
	Ptr             uint64               `json:"ptr,omitempty"`
	DataLen         uint32               `json:"data_len,omitempty"`
	PayloadSections []jsonPayloadSection `json:"payload_sections,omitempty"`
	RawString       string               `json:"raw_string,omitempty"`
	ProbeRetEnter   int32                `json:"probe_ret_enter"`
	ProbeRetExit    int32                `json:"probe_ret_exit"`
	PairedEnter     bool                 `json:"paired_enter,omitempty"`
}

type jsonPayloadSection struct {
	Kind       string `json:"kind"`
	Direction  string `json:"direction"`
	ArgIndex   int    `json:"arg_index"`
	Offset     uint32 `json:"offset"`
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
	Type               string `json:"type"`
	RingbufReserveFail uint64 `json:"ringbuf_reserve_fail"`
	RingbufCopyFail    uint64 `json:"ringbuf_copy_fail"`
	Available          bool   `json:"available"`
	Error              string `json:"error,omitempty"`
}

func newJSONSyscallEvent(eventRaw *bpfEvent, scMeta meta.Syscall, sections []handler.PayloadSection) jsonSyscallEvent {
	failed := eventRaw.Ret < 0 && eventRaw.Ret >= -4095
	errno := 0
	if failed {
		errno = int(-eventRaw.Ret)
	}
	return jsonSyscallEvent{
		Type:            "syscall",
		EventVersion:    eventRaw.EventVersion,
		EventType:       bpfEventTypeName(eventRaw),
		EventTypeID:     eventRaw.EventType,
		EventFlags:      eventRaw.EventFlags,
		Pid:             eventRaw.Pid,
		Tid:             eventRaw.Tid,
		SysID:           eventRaw.SysId,
		Syscall:         scMeta.Name,
		Args:            eventRaw.Args,
		Ret:             eventRaw.Ret,
		Failed:          failed,
		Errno:           errno,
		DurationNS:      eventRaw.Duration,
		EnterTimeNS:     eventRaw.EnterTime,
		Ptr:             eventRaw.Ptr,
		DataLen:         eventRaw.DataLen,
		PayloadSections: jsonPayloadSections(sections),
		ProbeRetEnter:   eventRaw.ProbeRetEnter,
		ProbeRetExit:    eventRaw.ProbeRetExit,
	}
}

func (s *traceSession) writeJSONRawEvent(eventRaw *bpfEvent, scMeta meta.Syscall) {
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	_ = json.NewEncoder(s.outWriter).Encode(ev)
}

func (s *traceSession) writeJSONLifecycleEvent(eventRaw *bpfEvent, task *TaskState) {
	ev := jsonLifecycleEvent{
		Type:         "lifecycle",
		EventVersion: eventRaw.EventVersion,
		EventType:    bpfEventTypeName(eventRaw),
		EventTypeID:  eventRaw.EventType,
		Action:       lifecycleActionName(eventRaw.EventFlags),
		ActionID:     eventRaw.EventFlags,
		Pid:          eventRaw.Pid,
		Tid:          eventRaw.Tid,
		Arg0:         eventRaw.Args[0],
		Arg1:         eventRaw.Args[1],
		TimeNS:       eventRaw.EnterTime,
	}
	if eventRaw.EventFlags == lifecycleExec {
		ev.Filename = lifecycleSnapshotString(eventRaw)
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
		Type:               "stats",
		RingbufReserveFail: stats.RingbufReserveFail,
		RingbufCopyFail:    stats.RingbufCopyFail,
		Available:          stats.Available,
		Error:              stats.Error,
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

func lifecycleSnapshotString(eventRaw *bpfEvent) string {
	if eventRaw.DataLen == 0 {
		return ""
	}
	n := int(eventRaw.DataLen)
	if n > len(eventRaw.StrArg) {
		n = len(eventRaw.StrArg)
	}
	data := eventRaw.StrArg[:n]
	if idx := bytes.IndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}
	return string(data)
}

func (s *traceSession) writeJSONEvent(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result, ctx *handler.Context, pendingEnter *pendingSyscallState) {
	ev := newJSONSyscallEvent(eventRaw, scMeta, ctx.PayloadSections)
	ev.ArgText = res.ArgParts
	ev.ReturnText = formatSyscallRet(scMeta.Name, eventRaw.Ret, res, ctx)
	ev.RawString = ctx.RawStrArg
	ev.PairedEnter = pendingEnter != nil && pendingEnter.genericEnterRaw
	_ = json.NewEncoder(s.outWriter).Encode(ev)
}

func bpfEventTypeName(eventRaw *bpfEvent) string {
	switch eventRaw.EventType {
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

func isLifecycleEvent(eventRaw *bpfEvent) bool {
	return eventRaw.EventType == bpfEventTypeLifecycle
}

func isGenericEnterEvent(eventRaw *bpfEvent) bool {
	return eventRaw.EventType == bpfEventTypeEnter && (eventRaw.EventFlags&bpfEventFlagGenericEnter) != 0
}

func shouldEmitStatus(eventRaw *bpfEvent, scMeta meta.Syscall, optsStatus successfulFailedOptions) bool {
	if optsStatus.successfulOnly || optsStatus.failedOnly || len(optsStatus.traceStatus) > 0 {
		if eventRaw.ProbeRetEnter == 3 {
			return false
		}
	}
	if eventRaw.ProbeRetEnter == 3 {
		return true
	}

	isFailed := eventRaw.Ret < 0 && eventRaw.Ret >= -4095
	if scMeta.Name == "exit" || scMeta.Name == "exit_group" {
		isFailed = false
	}
	if optsStatus.successfulOnly && isFailed {
		return false
	}
	if optsStatus.failedOnly && !isFailed {
		return false
	}
	if len(optsStatus.traceStatus) > 0 {
		if optsStatus.traceStatus["successful"] && !isFailed {
			return true
		}
		if optsStatus.traceStatus["failed"] && isFailed {
			return true
		}
		return false
	}
	return true
}

type successfulFailedOptions struct {
	successfulOnly bool
	failedOnly     bool
	traceStatus    map[string]bool
}
