package main

import (
	"fmt"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type syscallEventContext struct {
	raw                *bpfEvent
	view               syscallEventView
	statePID           int
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

// syscallEventView is the stable syscall field set used after context construction.
type syscallEventView struct {
	valid         bool
	eventVersion  uint16
	pid           uint32
	tid           uint32
	sysID         uint32
	eventType     uint16
	eventFlags    uint32
	args          [6]uint64
	ret           int64
	duration      uint64
	enterTime     uint64
	ptr           uint64
	dataLen       uint32
	stackID       int32
	probeRetEnter int32
	probeRetExit  int32
}

func newSyscallEventContext(s *traceSession, eventRaw *bpfEvent, statePID int, pendingEnter *pendingSyscallState) syscallEventContext {
	scMeta := syscallMeta(eventRaw.SysId)
	view := newSyscallEventViewFromBPF(eventRaw)
	isPath := syscallHasPathArg(scMeta)
	payloadSections := payloadSectionsForEvent(eventRaw, scMeta)
	pathText := decodePathText(s, view, scMeta, isPath, payloadSections)
	shouldPrint := true
	if s.opts != nil {
		shouldPrint = checkShouldPrintFromView(view, scMeta, pathText, isPath, statePID, s.opts, s.fdStateStore().PathMap())
	}
	bufferFileOffset, bufferFileOffsetOK := s.fdStateStore().BufferFileOffsetFromView(view, scMeta, statePID)
	ev := syscallEventContext{
		raw:                eventRaw,
		view:               view,
		statePID:           statePID,
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

func newSyscallEnterEventContext(eventRaw *bpfEvent, statePID int) syscallEventContext {
	return syscallEventContext{
		raw:      eventRaw,
		view:     newSyscallEventViewFromBPF(eventRaw),
		statePID: statePID,
		meta:     syscallMeta(eventRaw.SysId),
	}
}

func newSyscallEventViewFromBPF(eventRaw *bpfEvent) syscallEventView {
	if eventRaw == nil {
		return syscallEventView{}
	}
	return syscallEventView{
		valid:         true,
		eventVersion:  eventRaw.EventVersion,
		pid:           eventRaw.Pid,
		tid:           eventRaw.Tid,
		sysID:         eventRaw.SysId,
		eventType:     eventRaw.EventType,
		eventFlags:    eventRaw.EventFlags,
		args:          eventRaw.Args,
		ret:           eventRaw.Ret,
		duration:      eventRaw.Duration,
		enterTime:     eventRaw.EnterTime,
		ptr:           eventRaw.Ptr,
		dataLen:       eventRaw.DataLen,
		stackID:       eventRaw.StackId,
		probeRetEnter: eventRaw.ProbeRetEnter,
		probeRetExit:  eventRaw.ProbeRetExit,
	}
}

func (ev syscallEventContext) eventView() syscallEventView {
	if ev.view.valid {
		return ev.view
	}
	return newSyscallEventViewFromBPF(ev.raw)
}

func (ev syscallEventContext) outputPayloadSections() []handler.PayloadSection {
	if ev.payloadSections != nil {
		return ev.payloadSections
	}
	if ev.raw == nil {
		return nil
	}
	return payloadSectionsForEvent(ev.raw, ev.meta)
}

func (ev syscallEventContext) effectiveSyscallMeta() meta.Syscall {
	if ev.meta.Name != "" {
		return ev.meta
	}
	if ev.handlerContext != nil {
		return ev.handlerContext.ScMeta
	}
	return ev.meta
}

func (ev syscallEventContext) syscallName() string {
	return ev.effectiveSyscallMeta().Name
}

func (ev syscallEventContext) handlerContextForFormatting() *handler.Context {
	return ev.handlerContext
}

func (ev syscallEventContext) decodedPayloadSections() []handler.PayloadSection {
	if ev.handlerContext == nil {
		return nil
	}
	return ev.handlerContext.PayloadSections
}

func (ev syscallEventContext) returnText(res handler.Result) string {
	view := ev.eventView()
	return formatSyscallRet(ev.syscallName(), view.ret, res, ev.handlerContextForFormatting())
}

func (ev syscallEventContext) pairedGenericEnter() bool {
	return ev.pendingEnter != nil && ev.pendingEnter.genericEnterRaw
}

func (ev syscallEventContext) shouldSuppressOutput() bool {
	return ev.syscallName() == "arch_prctl" && ev.eventView().args[0] == 0x1002
}

func (ev syscallEventContext) recordSummary(stats *SummaryStats) {
	if stats == nil || !ev.shouldOutput() {
		return
	}
	view := ev.eventView()
	stats.Record(ev.syscallName(), view.duration, view.ret)
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

func decodePathText(s *traceSession, view syscallEventView, scMeta meta.Syscall, isPath bool, payloadSections []handler.PayloadSection) string {
	if !isPath {
		return ""
	}
	if text, ok := pathTextFromPayload(s, view, scMeta, payloadSections); ok {
		return text
	}
	return s.decoder.DecodeString(int(view.tid), view.ptr, nil, -1, scMeta.Name, 0)
}

func pathTextFromPayload(s *traceSession, view syscallEventView, scMeta meta.Syscall, payloadSections []handler.PayloadSection) (string, bool) {
	if argIndex, ok := simplePathPayloadArgIndex(scMeta.Name); ok {
		if text, ok := stringPayloadSectionText(s, view, scMeta, payloadSections, argIndex); ok {
			return text, true
		}
	}
	for _, section := range payloadSections {
		if section.Kind == handler.PayloadKindString && section.Direction == handler.PayloadDirectionIn &&
			section.ProbeRet == 0 && len(section.Data) > 0 && section.UserPtr == view.ptr {
			return s.decoder.DecodeString(int(view.tid), section.UserPtr, section.Data, section.ProbeRet, scMeta.Name, 0), true
		}
	}
	return "", false
}

func stringPayloadSectionText(
	s *traceSession,
	view syscallEventView,
	scMeta meta.Syscall,
	payloadSections []handler.PayloadSection,
	argIndex int,
) (string, bool) {
	for _, section := range payloadSections {
		if section.Kind == handler.PayloadKindString && section.Direction == handler.PayloadDirectionIn &&
			section.ArgIndex == argIndex && section.ProbeRet == 0 && len(section.Data) > 0 {
			return s.decoder.DecodeString(int(view.tid), section.UserPtr, section.Data, section.ProbeRet, scMeta.Name, 0), true
		}
	}
	return "", false
}

func (ev syscallEventContext) newHandlerContext(s *traceSession) *handler.Context {
	view := ev.eventView()
	return &handler.Context{
		Pid: int(view.pid), Tid: int(view.tid), TargetPid: ev.statePID, SysId: view.sysID,
		SysName: ev.meta.Name, Args: view.args, Ret: view.ret,
		ProbeRetEnter: view.probeRetEnter, ProbeRetExit: view.probeRetExit,
		PayloadSections:  ev.payloadSections,
		BufferFileOffset: ev.bufferFileOffset, BufferFileOffsetOK: ev.bufferFileOffsetOK,
		ScMeta: ev.meta, Decoder: s.decoder, Opts: s.opts, FdMap: s.fdStateStore().PathMap(),
		FdFiles: s.fdStateStore().FileMap(),
	}
}

func (ev syscallEventContext) shouldOutput() bool {
	return ev.shouldPrint
}

func (ev syscallEventContext) shouldRunHandler() bool {
	return ev.shouldPrint || ev.isFDStateSyscall()
}

func (ev syscallEventContext) shouldEmitRawEnter(opts *cli.Options, pathMap map[string]string) bool {
	if opts == nil {
		return false
	}
	if opts.DebugEvents {
		return true
	}
	return checkShouldPrintFromView(ev.eventView(), ev.meta, "", false, ev.statePID, opts, pathMap)
}

func (ev syscallEventContext) handleWith(handle func(string, *handler.Context) handler.Result) handler.Result {
	if handle == nil {
		return handler.Result{}
	}
	return handle(ev.syscallName(), ev.handlerContext)
}

func (s *traceSession) updateSummaryStats(ev syscallEventContext) {
	if s.opts == nil || (!s.opts.SummaryOnly && !s.opts.SummaryAndPrint) {
		return
	}
	ev.recordSummary(s.summaryStats())
}

func (ev syscallEventContext) isFDStateSyscall() bool {
	switch ev.syscallName() {
	case "open", "openat", "openat2", "creat", "dup", "dup2", "dup3", "close",
		"faccessat", "faccessat2", "chmodat", "mkdirat", "newfstatat", "fstat", "chdir", "fchdir":
		return true
	default:
		return false
	}
}

func (s *traceSession) updateFDState(ev syscallEventContext) {
	s.fdStateStore().UpdateFromSyscall(ev)
}

func (s *traceSession) cleanupClosedFD(ev syscallEventContext) {
	s.fdStateStore().CleanupClosedFDFromView(ev.eventView(), ev.meta, ev.statePID)
}

func (ev syscallEventContext) shouldEmitStatus(optsStatus successfulFailedOptions) bool {
	return ev.eventView().shouldEmitStatus(ev.syscallName(), optsStatus)
}

func (view syscallEventView) shouldEmitStatus(syscallName string, optsStatus successfulFailedOptions) bool {
	if optsStatus.successfulOnly || optsStatus.failedOnly || len(optsStatus.traceStatus) > 0 {
		if view.probeRetEnter == 3 {
			return false
		}
	}
	if view.probeRetEnter == 3 {
		return true
	}

	isFailed := view.ret < 0 && view.ret >= -4095
	if syscallName == "exit" || syscallName == "exit_group" {
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
