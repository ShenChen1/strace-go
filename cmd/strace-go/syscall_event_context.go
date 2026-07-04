package main

import (
	"fmt"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type syscallEventContext struct {
	raw                *bpfEvent
	statePID           int
	tid                int
	meta               meta.Syscall
	isPath             bool
	pathText           string
	shouldPrint        bool
	pendingEnter       *pendingSyscallState
	handlerContext     *handler.Context
	payloadSections    []handler.PayloadSection
	bufferFileOffset   int64
	bufferFileOffsetOK bool
}

func newSyscallEventContext(s *traceSession, eventRaw *bpfEvent, statePID int, pendingEnter *pendingSyscallState) syscallEventContext {
	scMeta := syscallMeta(eventRaw.SysId)
	isPath := syscallHasPathArg(scMeta)
	payloadSections := payloadSectionsForEvent(eventRaw, scMeta)
	pathText := decodePathText(s, eventRaw, scMeta, isPath, payloadSections)
	shouldPrint := true
	if s.opts != nil {
		shouldPrint = checkShouldPrint(eventRaw, scMeta, pathText, isPath, statePID, s.opts, s.fdStateStore().PathMap())
	}
	bufferFileOffset, bufferFileOffsetOK := s.bufferFileOffset(eventRaw, scMeta)
	ev := syscallEventContext{
		raw:                eventRaw,
		statePID:           statePID,
		tid:                int(eventRaw.Tid),
		meta:               scMeta,
		isPath:             isPath,
		pathText:           pathText,
		shouldPrint:        shouldPrint,
		pendingEnter:       pendingEnter,
		payloadSections:    payloadSections,
		bufferFileOffset:   bufferFileOffset,
		bufferFileOffsetOK: bufferFileOffsetOK,
	}
	ev.handlerContext = ev.newHandlerContext(s)
	return ev
}

func syscallMeta(sysID uint32) meta.Syscall {
	if scMeta, ok := meta.SyscallTable[sysID]; ok {
		return scMeta
	}
	return meta.Syscall{Name: unknownSyscallName(sysID)}
}

func unknownSyscallName(sysID uint32) string {
	return fmt.Sprintf("sys_%d", sysID)
}

func syscallHasPathArg(scMeta meta.Syscall) bool {
	for _, argName := range scMeta.Args {
		switch argName {
		case "filename", "pathname", "path", "oldname", "newname", "fs_name":
			return true
		}
	}
	return false
}

func decodePathText(s *traceSession, eventRaw *bpfEvent, scMeta meta.Syscall, isPath bool, payloadSections []handler.PayloadSection) string {
	if !isPath {
		return ""
	}
	if text, ok := pathTextFromPayload(s, eventRaw, scMeta, payloadSections); ok {
		return text
	}
	return s.decoder.DecodeString(int(eventRaw.Tid), eventRaw.Ptr, nil, -1, scMeta.Name, 0)
}

func pathTextFromPayload(s *traceSession, eventRaw *bpfEvent, scMeta meta.Syscall, payloadSections []handler.PayloadSection) (string, bool) {
	if argIndex, ok := simplePathPayloadArgIndex(scMeta.Name); ok {
		if text, ok := stringPayloadSectionText(s, eventRaw, scMeta, payloadSections, argIndex); ok {
			return text, true
		}
	}
	for _, section := range payloadSections {
		if section.Kind == handler.PayloadKindString && section.Direction == handler.PayloadDirectionIn &&
			section.ProbeRet == 0 && len(section.Data) > 0 && section.UserPtr == eventRaw.Ptr {
			return s.decoder.DecodeString(int(eventRaw.Tid), section.UserPtr, section.Data, section.ProbeRet, scMeta.Name, 0), true
		}
	}
	return "", false
}

func stringPayloadSectionText(
	s *traceSession,
	eventRaw *bpfEvent,
	scMeta meta.Syscall,
	payloadSections []handler.PayloadSection,
	argIndex int,
) (string, bool) {
	for _, section := range payloadSections {
		if section.Kind == handler.PayloadKindString && section.Direction == handler.PayloadDirectionIn &&
			section.ArgIndex == argIndex && section.ProbeRet == 0 && len(section.Data) > 0 {
			return s.decoder.DecodeString(int(eventRaw.Tid), section.UserPtr, section.Data, section.ProbeRet, scMeta.Name, 0), true
		}
	}
	return "", false
}

func (ev syscallEventContext) newHandlerContext(s *traceSession) *handler.Context {
	return &handler.Context{
		Pid: int(ev.raw.Pid), Tid: ev.tid, TargetPid: ev.statePID, SysId: ev.raw.SysId,
		SysName: ev.meta.Name, Args: ev.raw.Args, Ret: ev.raw.Ret,
		ProbeRetEnter: ev.raw.ProbeRetEnter, ProbeRetExit: ev.raw.ProbeRetExit,
		Ptr: ev.raw.Ptr, DataLen: ev.raw.DataLen, StrArgBuf: ev.raw.StrArg[:],
		PayloadSections:  ev.payloadSections,
		BufferFileOffset: ev.bufferFileOffset, BufferFileOffsetOK: ev.bufferFileOffsetOK,
		ScMeta: ev.meta, Decoder: s.decoder, Opts: s.opts, FdMap: s.fdStateStore().PathMap(),
		FdFiles: s.fdStateStore().FileMap(),
	}
}

func (s *traceSession) updateSummaryStats(ev syscallEventContext) {
	if s.opts == nil || (!s.opts.SummaryOnly && !s.opts.SummaryAndPrint) || !ev.shouldPrint {
		return
	}
	s.summaryStats().Record(ev.meta.Name, ev.raw.Duration, ev.raw.Ret)
}

func (ev syscallEventContext) isFDStateSyscall() bool {
	switch ev.meta.Name {
	case "open", "openat", "openat2", "creat", "dup", "dup2", "dup3", "close",
		"faccessat", "faccessat2", "chmodat", "mkdirat", "newfstatat", "fstat", "chdir", "fchdir":
		return true
	default:
		return false
	}
}

func (s *traceSession) updateFDState(ev syscallEventContext) {
	s.fdStateStore().UpdateFromEvent(ev.raw, ev.meta, ev.pathText, ev.statePID)
}

func (s *traceSession) cleanupClosedFD(ev syscallEventContext) {
	s.fdStateStore().CleanupClosedFD(ev.raw, ev.meta, ev.statePID)
}
