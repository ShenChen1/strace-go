package main

import (
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
	StackID         int32                `json:"stack_id"`
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
	Type           string `json:"type"`
	EventVersion   uint16 `json:"event_version,omitempty"`
	EventType      string `json:"event_type"`
	EventTypeID    uint16 `json:"event_type_id,omitempty"`
	EventFlags     uint32 `json:"event_flags,omitempty"`
	Action         string `json:"action"`
	ActionID       uint32 `json:"action_id,omitempty"`
	Pid            uint32 `json:"pid"`
	Tid            uint32 `json:"tid"`
	TaskTID        uint32 `json:"task_tid,omitempty"`
	TaskTGID       uint32 `json:"task_tgid,omitempty"`
	ParentTID      uint32 `json:"parent_tid,omitempty"`
	Alive          bool   `json:"alive"`
	Execed         bool   `json:"execed,omitempty"`
	TaskExecutable string `json:"task_executable,omitempty"`
	Filename       string `json:"filename,omitempty"`
	Arg0           uint64 `json:"arg0,omitempty"`
	Arg1           uint64 `json:"arg1,omitempty"`
	TimeNS         uint64 `json:"time_ns"`
}

type jsonReadyEvent struct {
	Type        string `json:"type"`
	TargetPID   int    `json:"target_pid"`
	AttachPIDs  []int  `json:"attach_pids,omitempty"`
	StartTimeNS uint64 `json:"start_time_ns,omitempty"`
	TimeNS      uint64 `json:"time_ns"`
}

type jsonPhaseEvent struct {
	Type        string `json:"type"`
	Phase       string `json:"phase"`
	StartTimeNS uint64 `json:"start_time_ns,omitempty"`
	DurationNS  uint64 `json:"duration_ns,omitempty"`
	TimeNS      uint64 `json:"time_ns"`
}

type jsonStatsEvent struct {
	Type                   string `json:"type"`
	RingbufReserveFail     uint64 `json:"ringbuf_reserve_fail"`
	RingbufCopyFail        uint64 `json:"ringbuf_copy_fail"`
	PayloadTruncatedEvents uint64 `json:"payload_truncated_events"`
	PendingUpdateFail      uint64 `json:"pending_update_fail"`
	OrphanExit             uint64 `json:"orphan_exit"`
	PendingMismatch        uint64 `json:"pending_mismatch"`
	LifecycleMapUpdateFail uint64 `json:"lifecycle_map_update_fail"`
	PendingStale           uint64 `json:"pending_stale"`
	RecordsRead            uint64 `json:"records_read"`
	RecordsDecoded         uint64 `json:"records_decoded"`
	RecordsInvalid         uint64 `json:"records_invalid"`
	RecordsRouted          uint64 `json:"records_routed"`
	ServiceEnabled         bool   `json:"service_enabled"`
	ServiceSampleRate      uint64 `json:"service_sample_rate"`
	BytesRead              uint64 `json:"bytes_read"`
	MaxRecordBytes         uint64 `json:"max_record_bytes"`
	MinRemainingBytes      uint64 `json:"min_remaining_bytes"`
	ServiceTimeNS          uint64 `json:"service_time_ns"`
	ServiceRecords         uint64 `json:"service_records"`
	MaxServiceTimeNS       uint64 `json:"max_service_time_ns"`
	MaxRemainingBytes      uint64 `json:"max_remaining_bytes"`
	Available              bool   `json:"available"`
	Error                  string `json:"error,omitempty"`
}

func newJSONReadyEventAt(targetPID int, attachPIDs []int, startTimeNS uint64, timeNS uint64) jsonReadyEvent {
	return jsonReadyEvent{
		Type:        "ready",
		TargetPID:   targetPID,
		AttachPIDs:  append([]int(nil), attachPIDs...),
		StartTimeNS: startTimeNS,
		TimeNS:      timeNS,
	}
}

func newJSONPhaseEvent(phase string, timeNS uint64) jsonPhaseEvent {
	return newJSONPhaseEventAt(phase, 0, timeNS)
}

func newJSONPhaseEventAt(phase string, startTimeNS uint64, timeNS uint64) jsonPhaseEvent {
	var durationNS uint64
	if startTimeNS > 0 && timeNS >= startTimeNS {
		durationNS = timeNS - startTimeNS
	}
	return jsonPhaseEvent{
		Type:        "phase",
		Phase:       phase,
		StartTimeNS: startTimeNS,
		DurationNS:  durationNS,
		TimeNS:      timeNS,
	}
}

func newJSONSyscallEventFromView(view syscallEventView, scMeta meta.Syscall, sections []handler.PayloadSection) jsonSyscallEvent {
	return newJSONSyscallEventFromViewWithPayloadStorage(view, scMeta, sections, nil)
}

func newJSONSyscallEventFromViewWithPayloadStorage(
	view syscallEventView,
	scMeta meta.Syscall,
	sections []handler.PayloadSection,
	payloadStorage []jsonPayloadSection,
) jsonSyscallEvent {
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
		StackID:         view.stackID,
		PayloadSections: jsonPayloadSectionsInto(payloadStorage, sections),
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

func newJSONStatsEvent(
	stats bpfRuntimeStats,
	pendingStale uint64,
	readerStats traceEventReaderStats,
) jsonStatsEvent {
	return jsonStatsEvent{
		Type:                   "stats",
		RingbufReserveFail:     stats.RingbufReserveFail,
		RingbufCopyFail:        stats.RingbufCopyFail,
		PayloadTruncatedEvents: stats.PayloadTruncatedEvents,
		PendingUpdateFail:      stats.PendingUpdateFail,
		OrphanExit:             stats.OrphanExit,
		PendingMismatch:        stats.PendingMismatch,
		LifecycleMapUpdateFail: stats.LifecycleMapUpdateFail,
		PendingStale:           pendingStale,
		RecordsRead:            readerStats.RecordsRead,
		RecordsDecoded:         readerStats.RecordsDecoded,
		RecordsInvalid:         readerStats.RecordsInvalid,
		RecordsRouted:          readerStats.RecordsRouted,
		ServiceEnabled:         readerStats.ServiceEnabled,
		ServiceSampleRate:      readerStats.ServiceSampleRate,
		BytesRead:              readerStats.BytesRead,
		MaxRecordBytes:         readerStats.MaxRecordBytes,
		MinRemainingBytes:      readerStats.MinRemainingBytes,
		ServiceTimeNS:          readerStats.ServiceTimeNS,
		ServiceRecords:         readerStats.ServiceRecords,
		MaxServiceTimeNS:       readerStats.MaxServiceTimeNS,
		MaxRemainingBytes:      readerStats.MaxRemainingBytes,
		Available:              stats.Available,
		Error:                  stats.Error,
	}
}

func (ev syscallEventContext) newJSONRawSyscallEvent() jsonSyscallEvent {
	return ev.newJSONRawSyscallEventWithPayloadStorage(nil)
}

func (ev syscallEventContext) newJSONRawSyscallEventWithPayloadStorage(
	payloadStorage []jsonPayloadSection,
) jsonSyscallEvent {
	return ev.newJSONSyscallEventWithPayloadStorage(ev.outputPayloadSections(), payloadStorage)
}

func (ev syscallEventContext) newJSONDecodedSyscallEvent(res handler.Result) jsonSyscallEvent {
	return ev.newJSONDecodedSyscallEventWithPayloadStorage(res, nil)
}

func (ev syscallEventContext) newJSONDecodedSyscallEventWithPayloadStorage(
	res handler.Result,
	payloadStorage []jsonPayloadSection,
) jsonSyscallEvent {
	jsonEvent := ev.newJSONSyscallEventWithPayloadStorage(ev.decodedPayloadSections(), payloadStorage)
	jsonEvent.ArgText = res.ArgParts
	jsonEvent.ReturnText = ev.returnText(res)
	jsonEvent.PairedEnter = ev.pairedGenericEnter()
	return jsonEvent
}

func (ev syscallEventContext) newJSONSyscallEvent(sections []handler.PayloadSection) jsonSyscallEvent {
	return ev.newJSONSyscallEventWithPayloadStorage(sections, nil)
}

func (ev syscallEventContext) newJSONSyscallEventWithPayloadStorage(
	sections []handler.PayloadSection,
	payloadStorage []jsonPayloadSection,
) jsonSyscallEvent {
	return newJSONSyscallEventFromViewWithPayloadStorage(
		ev.eventView(),
		ev.effectiveSyscallMeta(),
		sections,
		payloadStorage,
	)
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
