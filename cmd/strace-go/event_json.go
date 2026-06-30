package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

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
	iovecSectionElemSize            = 16
	iovecSectionMaxBytes            = 512
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

func payloadSectionsForEvent(eventRaw *bpfEvent, scMeta meta.Syscall) []handler.PayloadSection {
	switch scMeta.Name {
	case "write", "pwrite64":
		return payloadSectionFromWindow(eventRaw, handler.PayloadKindBytes, handler.PayloadDirectionIn, 1, 0, uint32Clamped(eventRaw.Args[2]), getArgProbeStatus(eventRaw.ProbeRetEnter, 1))
	case "read", "pread64":
		if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 {
			return nil
		}
		return payloadSectionFromWindow(eventRaw, handler.PayloadKindBytes, handler.PayloadDirectionOut, 1, handler.BpfExitArgOffset, uint32Clamped(uint64(eventRaw.Ret)), eventRaw.ProbeRetExit)
	case "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2", "vmsplice":
		return iovecPayloadSectionFromWindow(eventRaw, 1, 2, handler.BpfEnterArgOffset)
	case "process_vm_readv", "process_vm_writev":
		sections := iovecPayloadSectionFromWindow(eventRaw, 1, 2, handler.BpfEnterArgOffset)
		return append(sections, iovecPayloadSectionFromWindow(eventRaw, 3, 4, handler.BpfMiscArgOffset)...)
	case "getcwd":
		return exitBytesPayloadSectionFromRet(eventRaw, 0)
	case "readlink":
		return exitBytesPayloadSectionFromRet(eventRaw, 1)
	case "readlinkat":
		return exitBytesPayloadSectionFromRet(eventRaw, 2)
	case "open", "creat":
		return stringPayloadSectionFromWindow(eventRaw, 0)
	case "openat", "openat2":
		return stringPayloadSectionFromWindow(eventRaw, 1)
	default:
		return nil
	}
}

func stringPayloadSectionFromWindow(eventRaw *bpfEvent, argIndex int) []handler.PayloadSection {
	data, ok := eventPayloadWindow(eventRaw, 0, 4097)
	if !ok {
		return nil
	}
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul+1]
	}
	section := newPayloadSection(eventRaw, handler.PayloadKindString, handler.PayloadDirectionIn, argIndex, 0, uint32(len(data)), getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex), data)
	return []handler.PayloadSection{section}
}

func exitBytesPayloadSectionFromRet(eventRaw *bpfEvent, argIndex int) []handler.PayloadSection {
	if !isExitEvent(eventRaw) || eventRaw.Ret <= 0 {
		return nil
	}
	return payloadSectionFromWindow(eventRaw, handler.PayloadKindBytes, handler.PayloadDirectionOut, argIndex, handler.BpfExitArgOffset, uint32Clamped(uint64(eventRaw.Ret)), eventRaw.ProbeRetExit)
}

func iovecPayloadSectionFromWindow(eventRaw *bpfEvent, argIndex int, countIndex int, offset int) []handler.PayloadSection {
	if countIndex < 0 || countIndex >= len(eventRaw.Args) {
		return nil
	}
	userLen := iovecUserLen(eventRaw.Args[countIndex])
	if userLen == 0 {
		return nil
	}
	maxLen := int(userLen)
	if maxLen > iovecSectionMaxBytes {
		maxLen = iovecSectionMaxBytes
	}
	data, ok := eventPayloadWindow(eventRaw, offset, maxLen)
	if !ok {
		return nil
	}
	section := newPayloadSection(eventRaw, handler.PayloadKindIovec, handler.PayloadDirectionIn, argIndex, offset, userLen, getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex), data)
	return []handler.PayloadSection{section}
}

func iovecUserLen(count uint64) uint32 {
	if count > uint64(^uint32(0))/iovecSectionElemSize {
		return ^uint32(0)
	}
	return uint32(count * iovecSectionElemSize)
}

func payloadSectionFromWindow(eventRaw *bpfEvent, kind handler.PayloadKind, direction handler.PayloadDirection, argIndex int, offset int, userLen uint32, probeRet int32) []handler.PayloadSection {
	data, ok := eventPayloadWindow(eventRaw, offset, int(userLen))
	if !ok {
		return nil
	}
	section := newPayloadSection(eventRaw, kind, direction, argIndex, offset, userLen, probeRet, data)
	return []handler.PayloadSection{section}
}

func eventPayloadWindow(eventRaw *bpfEvent, offset int, maxLen int) ([]byte, bool) {
	if offset < 0 || maxLen <= 0 || eventRaw.DataLen == 0 {
		return nil, false
	}
	if uint32(offset) >= eventRaw.DataLen || offset >= len(eventRaw.StrArg) {
		return nil, false
	}
	end := int(eventRaw.DataLen)
	if end > len(eventRaw.StrArg) {
		end = len(eventRaw.StrArg)
	}
	if limit := offset + maxLen; limit < end {
		end = limit
	}
	if end <= offset {
		return nil, false
	}
	return eventRaw.StrArg[offset:end], true
}

func newPayloadSection(eventRaw *bpfEvent, kind handler.PayloadKind, direction handler.PayloadDirection, argIndex int, offset int, userLen uint32, probeRet int32, data []byte) handler.PayloadSection {
	section := handler.PayloadSection{
		Kind:      kind,
		Direction: direction,
		ArgIndex:  argIndex,
		Offset:    uint32(offset),
		UserLen:   userLen,
		CopiedLen: uint32(len(data)),
		ProbeRet:  probeRet,
		Data:      data,
	}
	if argIndex >= 0 && argIndex < len(eventRaw.Args) {
		section.UserPtr = eventRaw.Args[argIndex]
	}
	return section
}

func jsonPayloadSections(sections []handler.PayloadSection) []jsonPayloadSection {
	if len(sections) == 0 {
		return nil
	}
	out := make([]jsonPayloadSection, 0, len(sections))
	for _, section := range sections {
		out = append(out, jsonPayloadSection{
			Kind:       string(section.Kind),
			Direction:  string(section.Direction),
			ArgIndex:   section.ArgIndex,
			Offset:     section.Offset,
			UserPtr:    section.UserPtr,
			UserLen:    section.UserLen,
			CopiedLen:  section.CopiedLen,
			ProbeRet:   section.ProbeRet,
			DataBase64: base64.StdEncoding.EncodeToString(section.Data),
		})
	}
	return out
}

func uint32Clamped(v uint64) uint32 {
	if v > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
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
