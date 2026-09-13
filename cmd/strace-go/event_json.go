package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type jsonSyscallEvent struct {
	traceRecordIntegrity
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
	returnTextName  string
	returnTextRet   int64
	returnTextRes   handler.Result
	returnTextCtx   *handler.Context
	hasReturnText   bool
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
	rawData    []byte
}

type jsonLifecycleEvent struct {
	traceRecordIntegrity
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
	Integrity                  traceIntegritySnapshot `json:"integrity"`
	Type                       string                 `json:"type"`
	RingbufReserveFail         uint64                 `json:"ringbuf_reserve_fail"`
	RingbufCopyFail            uint64                 `json:"ringbuf_copy_fail"`
	PayloadTruncatedEvents     uint64                 `json:"payload_truncated_events"`
	PendingUpdateFail          uint64                 `json:"pending_update_fail"`
	OrphanExit                 uint64                 `json:"orphan_exit"`
	OrphanFirstPid             uint64                 `json:"orphan_first_pid"`
	OrphanFirstTid             uint64                 `json:"orphan_first_tid"`
	OrphanFirstSysID           uint64                 `json:"orphan_first_sys_id"`
	OrphanFirstRet             int64                  `json:"orphan_first_ret"`
	OrphanFirstReason          uint64                 `json:"orphan_first_reason"`
	OrphanFirstTimeNS          uint64                 `json:"orphan_first_time_ns"`
	OrphanLastPid              uint64                 `json:"orphan_last_pid"`
	OrphanLastTid              uint64                 `json:"orphan_last_tid"`
	OrphanLastSysID            uint64                 `json:"orphan_last_sys_id"`
	OrphanLastRet              int64                  `json:"orphan_last_ret"`
	OrphanLastReason           uint64                 `json:"orphan_last_reason"`
	OrphanLastTimeNS           uint64                 `json:"orphan_last_time_ns"`
	PendingMismatch            uint64                 `json:"pending_mismatch"`
	LifecycleMapUpdateFail     uint64                 `json:"lifecycle_map_update_fail"`
	LifecycleForkSeen          uint64                 `json:"lifecycle_fork_seen"`
	LifecycleForkTracked       uint64                 `json:"lifecycle_fork_parent_tracked"`
	LifecycleForkUntracked     uint64                 `json:"lifecycle_fork_parent_untracked"`
	LifecycleForkInstalled     uint64                 `json:"lifecycle_fork_child_filter_installed"`
	LifecycleForkFailed        uint64                 `json:"lifecycle_fork_child_filter_failed"`
	LifecycleExecSeen          uint64                 `json:"lifecycle_exec_seen"`
	LifecycleExecUntracked     uint64                 `json:"lifecycle_exec_untracked"`
	LifecycleExitSeen          uint64                 `json:"lifecycle_exit_seen"`
	LifecycleExitUntracked     uint64                 `json:"lifecycle_exit_untracked"`
	PendingStale               uint64                 `json:"pending_stale"`
	RecordsRead                uint64                 `json:"records_read"`
	ProducerAttemptsLowerBound uint64                 `json:"producer_attempts_lower_bound"`
	RecordsDecoded             uint64                 `json:"records_decoded"`
	RecordsInvalid             uint64                 `json:"records_invalid"`
	RecordsRouted              uint64                 `json:"records_routed"`
	ServiceEnabled             bool                   `json:"service_enabled"`
	ServiceSampleRate          uint64                 `json:"service_sample_rate"`
	BytesRead                  uint64                 `json:"bytes_read"`
	MaxRecordBytes             uint64                 `json:"max_record_bytes"`
	ReadTimeNS                 uint64                 `json:"read_time_ns"`
	DecodeTimeNS               uint64                 `json:"decode_time_ns"`
	SinkTimeNS                 uint64                 `json:"sink_time_ns"`
	MinRemainingBytes          uint64                 `json:"min_remaining_bytes"`
	ServiceTimeNS              uint64                 `json:"service_time_ns"`
	ServiceRecords             uint64                 `json:"service_records"`
	MaxServiceTimeNS           uint64                 `json:"max_service_time_ns"`
	MaxRemainingBytes          uint64                 `json:"max_remaining_bytes"`
	SyscallOutputBytes         uint64                 `json:"syscall_output_bytes"`
	SyscallOutputWrites        uint64                 `json:"syscall_output_writes"`
	SyscallOutputWriteErrors   uint64                 `json:"syscall_output_write_errors"`
	SyscallWriteTimeNS         uint64                 `json:"syscall_write_time_ns"`
	SyscallWriteTimeSamples    uint64                 `json:"syscall_write_time_samples"`
	StageEnabled               bool                   `json:"stage_enabled"`
	StageSampleRate            uint64                 `json:"stage_sample_rate"`
	StateTimeNS                uint64                 `json:"state_time_ns"`
	StateRecords               uint64                 `json:"state_records"`
	MaxStateTimeNS             uint64                 `json:"max_state_time_ns"`
	DispatchTimeNS             uint64                 `json:"dispatch_time_ns"`
	DispatchRecords            uint64                 `json:"dispatch_records"`
	MaxDispatchTimeNS          uint64                 `json:"max_dispatch_time_ns"`
	Available                  bool                   `json:"available"`
	Error                      string                 `json:"error,omitempty"`
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
	return newJSONSyscallEventFromViewWithPayloadMode(view, scMeta, sections, payloadStorage, false)
}

func newJSONSyscallEventFromViewWithRawPayloadStorage(
	view syscallEventView,
	scMeta meta.Syscall,
	sections []handler.PayloadSection,
	payloadStorage []jsonPayloadSection,
) jsonSyscallEvent {
	return newJSONSyscallEventFromViewWithPayloadMode(view, scMeta, sections, payloadStorage, true)
}

func newJSONSyscallEventFromViewWithPayloadMode(
	view syscallEventView,
	scMeta meta.Syscall,
	sections []handler.PayloadSection,
	payloadStorage []jsonPayloadSection,
	rawPayload bool,
) jsonSyscallEvent {
	failed, errno := syscallFailure(view.ret)
	var payloadSections []jsonPayloadSection
	if rawPayload {
		payloadSections = jsonPayloadSectionsIntoRaw(payloadStorage, sections)
	} else {
		payloadSections = jsonPayloadSectionsInto(payloadStorage, sections)
	}
	return jsonSyscallEvent{
		traceRecordIntegrity: view.integrity,
		Type:                 "syscall",
		EventVersion:         view.eventVersion,
		EventType:            bpfEventTypeNameFromID(view.eventType),
		EventTypeID:          view.eventType,
		EventFlags:           view.eventFlags,
		Pid:                  view.pid,
		Tid:                  view.tid,
		SysID:                view.sysID,
		Syscall:              scMeta.Name,
		Args:                 view.args,
		Ret:                  view.ret,
		Failed:               failed,
		Errno:                errno,
		DurationNS:           view.duration,
		EnterTimeNS:          view.enterTime,
		StackID:              view.stackID,
		PayloadSections:      payloadSections,
		ProbeRetEnter:        view.probeRetEnter,
		ProbeRetExit:         view.probeRetExit,
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
	outputStats traceJSONOutputStats,
) jsonStatsEvent {
	return jsonStatsEvent{
		Integrity:                  readerStats.Integrity,
		Type:                       "stats",
		RingbufReserveFail:         stats.RingbufReserveFail,
		RingbufCopyFail:            stats.RingbufCopyFail,
		PayloadTruncatedEvents:     stats.PayloadTruncatedEvents,
		PendingUpdateFail:          stats.PendingUpdateFail,
		OrphanExit:                 stats.OrphanExit,
		OrphanFirstPid:             stats.OrphanFirstPid,
		OrphanFirstTid:             stats.OrphanFirstTid,
		OrphanFirstSysID:           stats.OrphanFirstSysID,
		OrphanFirstRet:             stats.OrphanFirstRet,
		OrphanFirstReason:          stats.OrphanFirstReason,
		OrphanFirstTimeNS:          stats.OrphanFirstTimeNS,
		OrphanLastPid:              stats.OrphanLastPid,
		OrphanLastTid:              stats.OrphanLastTid,
		OrphanLastSysID:            stats.OrphanLastSysID,
		OrphanLastRet:              stats.OrphanLastRet,
		OrphanLastReason:           stats.OrphanLastReason,
		OrphanLastTimeNS:           stats.OrphanLastTimeNS,
		PendingMismatch:            stats.PendingMismatch,
		LifecycleMapUpdateFail:     stats.LifecycleMapUpdateFail,
		LifecycleForkSeen:          stats.LifecycleForkSeen,
		LifecycleForkTracked:       stats.LifecycleForkTracked,
		LifecycleForkUntracked:     stats.LifecycleForkUntracked,
		LifecycleForkInstalled:     stats.LifecycleForkInstalled,
		LifecycleForkFailed:        stats.LifecycleForkFailed,
		LifecycleExecSeen:          stats.LifecycleExecSeen,
		LifecycleExecUntracked:     stats.LifecycleExecUntracked,
		LifecycleExitSeen:          stats.LifecycleExitSeen,
		LifecycleExitUntracked:     stats.LifecycleExitUntracked,
		PendingStale:               pendingStale,
		RecordsRead:                readerStats.RecordsRead,
		ProducerAttemptsLowerBound: producerAttemptLowerBound(stats, readerStats),
		RecordsDecoded:             readerStats.RecordsDecoded,
		RecordsInvalid:             readerStats.RecordsInvalid,
		RecordsRouted:              readerStats.RecordsRouted,
		ServiceEnabled:             readerStats.ServiceEnabled,
		ServiceSampleRate:          readerStats.ServiceSampleRate,
		BytesRead:                  readerStats.BytesRead,
		MaxRecordBytes:             readerStats.MaxRecordBytes,
		ReadTimeNS:                 readerStats.ReadTimeNS,
		DecodeTimeNS:               readerStats.DecodeTimeNS,
		SinkTimeNS:                 readerStats.SinkTimeNS,
		MinRemainingBytes:          readerStats.MinRemainingBytes,
		ServiceTimeNS:              readerStats.ServiceTimeNS,
		ServiceRecords:             readerStats.ServiceRecords,
		MaxServiceTimeNS:           readerStats.MaxServiceTimeNS,
		MaxRemainingBytes:          readerStats.MaxRemainingBytes,
		SyscallOutputBytes:         outputStats.SyscallBytesWritten,
		SyscallOutputWrites:        outputStats.SyscallWriteCalls,
		SyscallOutputWriteErrors:   outputStats.SyscallWriteErrors,
		SyscallWriteTimeNS:         outputStats.SyscallWriteTimeNS,
		SyscallWriteTimeSamples:    outputStats.SyscallWriteTimeSamples,
		StageEnabled:               readerStats.StageEnabled,
		StageSampleRate:            readerStats.StageSampleRate,
		StateTimeNS:                readerStats.StateTimeNS,
		StateRecords:               readerStats.StateRecords,
		MaxStateTimeNS:             readerStats.MaxStateTimeNS,
		DispatchTimeNS:             readerStats.DispatchTimeNS,
		DispatchRecords:            readerStats.DispatchRecords,
		MaxDispatchTimeNS:          readerStats.MaxDispatchTimeNS,
		Available:                  stats.Available,
		Error:                      stats.Error,
	}
}

func (ev syscallEventContext) newJSONRawSyscallEvent() jsonSyscallEvent {
	return ev.newJSONRawSyscallEventWithPayloadStorage(nil)
}

func (ev syscallEventContext) newJSONRawSyscallEventWithPayloadStorage(
	payloadStorage []jsonPayloadSection,
) jsonSyscallEvent {
	return ev.newJSONSyscallEventWithRawPayloadStorage(ev.outputPayloadSections(), payloadStorage)
}

func (ev syscallEventContext) newJSONDecodedSyscallEvent(res handler.Result) jsonSyscallEvent {
	return ev.newJSONDecodedSyscallEventWithPayloadStorage(res, nil)
}

func (ev syscallEventContext) newJSONDecodedSyscallEventWithPayloadStorage(
	res handler.Result,
	payloadStorage []jsonPayloadSection,
) jsonSyscallEvent {
	jsonEvent := ev.newJSONSyscallEventWithRawPayloadStorage(ev.decodedPayloadSections(), payloadStorage)
	jsonEvent.ArgText = res.ArgParts
	jsonEvent.returnTextName = ev.syscallName()
	jsonEvent.returnTextRet = ev.eventView().ret
	jsonEvent.returnTextRes = res
	jsonEvent.returnTextCtx = ev.handlerContextForFormatting()
	jsonEvent.hasReturnText = true
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

func (ev syscallEventContext) newJSONSyscallEventWithRawPayloadStorage(
	sections []handler.PayloadSection,
	payloadStorage []jsonPayloadSection,
) jsonSyscallEvent {
	return newJSONSyscallEventFromViewWithRawPayloadStorage(
		ev.eventView(), ev.effectiveSyscallMeta(), sections, payloadStorage,
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
	statusSet      bool
}

func (o successfulFailedOptions) hasStatusSet() bool {
	return o.statusSet || len(o.traceStatus) > 0
}
