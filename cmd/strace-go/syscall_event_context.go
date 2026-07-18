package main

import (
	"fmt"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type syscallEventContext struct {
	view            syscallEventView
	statePID        int
	meta            meta.Syscall
	isPath          bool
	pathText        string
	shouldPrint     bool
	pendingEnter    *pendingSyscallState
	handlerContext  *handler.Context
	payloadSections []handler.PayloadSection
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
	stackID       int32
	probeRetEnter int32
	probeRetExit  int32
}

func newSyscallEventContextFromView(
	s *traceSession,
	view syscallEventView,
	statePID int,
	pendingEnter *pendingSyscallState,
	currentPayload []handler.PayloadSection,
) syscallEventContext {
	scMeta := syscallMeta(view.sysID)
	isPath := syscallHasPathArg(scMeta)
	payloadSections := mergePendingPayloadSections(pendingEnter, currentPayload)
	pathText := decodePathText(s, view, scMeta, isPath, payloadSections)
	shouldPrint := true
	if s.opts != nil {
		shouldPrint = checkShouldPrintFromView(view, scMeta, pathText, isPath, statePID, s.opts, s.fdStateStore().PathMap())
	}
	ev := syscallEventContext{
		view:            view,
		statePID:        statePID,
		meta:            scMeta,
		isPath:          isPath,
		pathText:        pathText,
		shouldPrint:     shouldPrint,
		pendingEnter:    pendingEnter,
		payloadSections: payloadSections,
	}
	ev.handlerContext = ev.newHandlerContext(s)
	return ev
}

func mergePendingPayloadSections(pendingEnter *pendingSyscallState, current []handler.PayloadSection) []handler.PayloadSection {
	if pendingEnter == nil || len(pendingEnter.payloadSections) == 0 {
		return current
	}
	merged := make([]handler.PayloadSection, 0, len(pendingEnter.payloadSections)+len(current))
	for _, section := range pendingEnter.payloadSections {
		if hasEquivalentPayloadSection(current, section) {
			continue
		}
		merged = append(merged, section)
	}
	return append(merged, current...)
}

func hasEquivalentPayloadSection(sections []handler.PayloadSection, want handler.PayloadSection) bool {
	for _, section := range sections {
		if section.Kind == want.Kind &&
			section.Direction == want.Direction &&
			section.ArgIndex == want.ArgIndex &&
			section.UserPtr == want.UserPtr {
			return true
		}
	}
	return false
}

func newSyscallEnterEventContext(view syscallEventView, statePID int, payloadSections []handler.PayloadSection) syscallEventContext {
	scMeta := syscallMeta(view.sysID)
	return syscallEventContext{
		view:            view,
		statePID:        statePID,
		meta:            scMeta,
		payloadSections: payloadSections,
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
		stackID:       eventRaw.StackId,
		probeRetEnter: eventRaw.ProbeRetEnter,
		probeRetExit:  eventRaw.ProbeRetExit,
	}
}

func (ev syscallEventContext) eventView() syscallEventView {
	return ev.view
}

func (ev syscallEventContext) outputPayloadSections() []handler.PayloadSection {
	return ev.payloadSections
}

func (ev syscallEventContext) effectiveSyscallMeta() meta.Syscall {
	if ev.meta.Name != "" {
		return ev.meta
	}
	if ev.handlerContext != nil {
		if ev.handlerContext.ScMeta.Name != "" {
			return ev.handlerContext.ScMeta
		}
		if ev.handlerContext.SysName != "" {
			return meta.Syscall{Name: ev.handlerContext.SysName}
		}
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

func (ev syscallEventContext) updateFDOffsets(store *FDStateStore) {
	if store == nil {
		return
	}
	store.updateOffsetsFromView(ev.eventView(), ev.effectiveSyscallMeta(), ev.statePID)
}

func (ev syscallEventContext) cleanupClosedFD(store *FDStateStore) {
	if store == nil {
		return
	}
	store.cleanupClosedFDFromView(ev.eventView(), ev.effectiveSyscallMeta(), ev.statePID)
}

func (ev syscallEventContext) updateFDState(store *FDStateStore) {
	if store == nil {
		return
	}
	store.update(ev.fdStateUpdate())
}

func (ev syscallEventContext) fdStateUpdate() fdStateUpdate {
	view := ev.eventView()
	return fdStateUpdate{
		source: fdStateSource{
			view:            view,
			payloadSections: ev.outputPayloadSections(),
			procTid:         view.tid,
		},
		meta:      ev.effectiveSyscallMeta(),
		pathText:  ev.pathText,
		targetPID: ev.statePID,
	}
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
	scMeta := ev.effectiveSyscallMeta()
	return &handler.Context{
		Pid: int(view.pid), Tid: int(view.tid), TargetPid: ev.statePID, SysId: view.sysID,
		SysName: scMeta.Name, Args: view.args, Ret: view.ret,
		ProbeRetEnter: view.probeRetEnter, ProbeRetExit: view.probeRetExit,
		PayloadSections: ev.outputPayloadSections(),
		ScMeta:          scMeta, Decoder: s.decoder, Opts: s.opts, FdMap: s.fdStateStore().PathMap(),
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
	return checkShouldPrintFromView(ev.eventView(), ev.effectiveSyscallMeta(), "", false, ev.statePID, opts, pathMap)
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
	ev.updateFDState(s.fdStateStore())
}

func (s *traceSession) cleanupClosedFD(ev syscallEventContext) {
	ev.cleanupClosedFD(s.fdStateStore())
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
