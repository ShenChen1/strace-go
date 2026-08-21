package main

import (
	"fmt"

	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

var _ handler.SnapshotDecoder = (*event.Decoder)(nil)

type syscallEventContext struct {
	view            syscallEventView
	statePID        int
	meta            meta.Syscall
	fdFlags         fdFlagDecoder
	filter          traceFilterOptions
	pathText        string
	pathArguments   []event.PathArgument
	shouldPrint     bool
	pendingEnter    *pendingSyscallSnapshot
	handlerContext  *handler.Context
	contextRecycler *handlerContextRecycler
	payloadSections []handler.PayloadSection
	eventFDView     eventFDStateView
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
	stackID       int32
	probeRetEnter int32
	probeRetExit  int32
}

type syscallEventContextDeps struct {
	decoder         handler.SnapshotDecoder
	handlerOpts     handler.OptionsPort
	filter          traceFilterOptions
	catalog         meta.CatalogPort
	syscallMetadata *syscallMetadataTable
	fdState         handler.FDStateReader
	fdPath          event.FDPathReader
	registry        handler.RegistryPort
	handlerDispatch handler.HandlerDispatchPort
	runtime         handler.RuntimeServices
	contextPool     *handlerContextRecycler
}

type syscallEventContextDependencySource interface {
	eventContextDependencies() syscallEventContextDeps
}

type traceSummaryRecorder interface {
	Record(name string, duration uint64, ret int64)
}

func newSyscallEventContextDeps(source syscallEventContextDependencySource) syscallEventContextDeps {
	if source == nil {
		return syscallEventContextDeps{}
	}
	return source.eventContextDependencies()
}

func newSyscallEventContextDepsWithRegistry(
	source syscallEventContextDependencySource,
	registry handler.RegistryPort,
) syscallEventContextDeps {
	deps := newSyscallEventContextDeps(source)
	deps.registry = registry
	return deps
}

func (deps syscallEventContextDeps) fdPathReader() event.FDPathReader {
	return deps.fdPath
}

func (deps syscallEventContextDeps) fdStateReader() handler.FDStateReader {
	if deps.fdState == nil {
		return nil
	}
	return deps.fdState
}

func (deps syscallEventContextDeps) runtimeService() handler.RuntimeServices {
	return deps.runtime
}

func newSyscallEventContextFromView(
	s syscallEventContextDependencySource,
	view syscallEventView,
	statePID int,
	pendingEnter *pendingSyscallSnapshot,
	currentPayload []handler.PayloadSection,
) syscallEventContext {
	return newSyscallEventContextFromViewWithDeps(newSyscallEventContextDeps(s), view, statePID, pendingEnter, currentPayload)
}

func newSyscallEventContextFromViewWithDeps(
	deps syscallEventContextDeps,
	view syscallEventView,
	statePID int,
	pendingEnter *pendingSyscallSnapshot,
	currentPayload []handler.PayloadSection,
) syscallEventContext {
	scMeta := lookupSyscallMetadata(deps.syscallMetadata, view.sysID)
	if canUseFastSyscallEventContext(view, pendingEnter, currentPayload, deps.filter) {
		ev := syscallEventContext{
			view:            view,
			statePID:        statePID,
			meta:            scMeta,
			fdFlags:         deps.catalog,
			filter:          deps.filter,
			shouldPrint:     true,
			pendingEnter:    pendingEnter,
			contextRecycler: deps.contextPool,
		}
		ev.handlerContext = ev.newHandlerContext(deps)
		return ev
	}
	payloadSections := mergePendingPayloadSections(pendingEnter, currentPayload)
	fdPathOverlay := fdPathOverlayFromSections(payloadSections)
	eventFDView := fdPathOverlay.resolve(view)
	pathArguments := decodePathArguments(deps, view, scMeta, payloadSections)
	pathText := primaryPathText(pathArguments)
	shouldPrint := true
	if deps.filter != nil && !deps.filter.IsUnfiltered() {
		shouldPrint = checkShouldPrintFromView(printFilterRequest{
			view:            view,
			scMeta:          scMeta,
			pathArguments:   pathArguments,
			targetPid:       statePID,
			filter:          deps.filter,
			fdState:         deps.fdPathReader(),
			eventFD:         eventFDView,
			payloadSections: payloadSections,
		})
	}
	ev := syscallEventContext{
		view:            view,
		statePID:        statePID,
		meta:            scMeta,
		fdFlags:         deps.catalog,
		filter:          deps.filter,
		pathText:        pathText,
		pathArguments:   pathArguments,
		shouldPrint:     shouldPrint,
		pendingEnter:    pendingEnter,
		contextRecycler: deps.contextPool,
		payloadSections: payloadSections,
		eventFDView:     eventFDView,
	}
	ev.handlerContext = ev.newHandlerContext(deps)
	return ev
}

func canUseFastSyscallEventContext(
	view syscallEventView,
	pendingEnter *pendingSyscallSnapshot,
	currentPayload []handler.PayloadSection,
	filter traceFilterOptions,
) bool {
	if !view.valid || len(currentPayload) > 0 {
		return false
	}
	if pendingEnter != nil && len(pendingEnter.payloadSections) > 0 {
		return false
	}
	return filter == nil || filter.IsUnfiltered()
}

func mergePendingPayloadSections(pendingEnter *pendingSyscallSnapshot, current []handler.PayloadSection) []handler.PayloadSection {
	if pendingEnter == nil || len(pendingEnter.payloadSections) == 0 {
		return current
	}
	if len(current) == 0 {
		return pendingEnter.payloadSections
	}

	owned := pendingEnter.payloadSections[:0]
	for _, section := range pendingEnter.payloadSections {
		if hasEquivalentPayloadSection(current, section) {
			continue
		}
		owned = append(owned, section)
	}
	owned = append(owned, current...)
	pendingEnter.payloadSections = owned
	return owned
}

func hasEquivalentPayloadSection(sections []handler.PayloadSection, want handler.PayloadSection) bool {
	for _, section := range sections {
		if section.Kind == want.Kind &&
			section.Direction == want.Direction &&
			section.ArgIndex == want.ArgIndex &&
			section.UserPtr == want.UserPtr &&
			nestedFDPathIdentityMatches(section, want) {
			return true
		}
	}
	return false
}

func nestedFDPathIdentityMatches(left, right handler.PayloadSection) bool {
	if left.Kind != handler.PayloadKindFDPath ||
		left.ArgIndex != handler.PayloadFDPathNestedArgIndex {
		return true
	}
	leftFD, leftOK := nestedFDPathSnapshotFD(left)
	rightFD, rightOK := nestedFDPathSnapshotFD(right)
	if !leftOK && !rightOK {
		return true
	}
	return leftOK && rightOK && leftFD == rightFD
}

func nestedFDPathSnapshotFD(section handler.PayloadSection) (int32, bool) {
	snapshot, ok := handler.DecodeFDPathSnapshot(section.Data)
	if !ok || !snapshot.HasObservation {
		return 0, false
	}
	return snapshot.Observation.FD, true
}

func newSyscallEnterEventContextWithFlagDecoder(
	view syscallEventView,
	statePID int,
	payloadSections []handler.PayloadSection,
	flagDecoder fdFlagDecoder,
	filter traceFilterOptions,
) syscallEventContext {
	return newSyscallEnterEventContextFromConfig(syscallEnterEventContextConfig{
		view:            view,
		statePID:        statePID,
		payloadSections: payloadSections,
		flagDecoder:     flagDecoder,
		filter:          filter,
	})
}

type syscallEnterEventContextConfig struct {
	view            syscallEventView
	statePID        int
	payloadSections []handler.PayloadSection
	flagDecoder     fdFlagDecoder
	filter          traceFilterOptions
	syscallMetadata *syscallMetadataTable
}

func newSyscallEnterEventContextFromDeps(
	deps syscallEventContextDeps,
	view syscallEventView,
	statePID int,
	payloadSections []handler.PayloadSection,
) syscallEventContext {
	return newSyscallEnterEventContextFromConfig(syscallEnterEventContextConfig{
		view:            view,
		statePID:        statePID,
		payloadSections: payloadSections,
		flagDecoder:     deps.catalog,
		filter:          deps.filter,
		syscallMetadata: deps.syscallMetadata,
	})
}

func newSyscallEnterEventContextFromConfig(
	config syscallEnterEventContextConfig,
) syscallEventContext {
	scMeta := lookupSyscallMetadata(config.syscallMetadata, config.view.sysID)
	fdPathOverlay := fdPathOverlayFromSections(config.payloadSections)
	eventFDView := fdPathOverlay.resolve(config.view)
	return syscallEventContext{
		view:            config.view,
		statePID:        config.statePID,
		meta:            scMeta,
		fdFlags:         config.flagDecoder,
		filter:          config.filter,
		payloadSections: config.payloadSections,
		eventFDView:     eventFDView,
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
	if ev.meta.Name != "" {
		return ev.meta.Name
	}
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

func (ev syscallEventContext) recordSummary(recorder traceSummaryRecorder) {
	if recorder == nil || !ev.shouldOutput() {
		return
	}
	view := ev.eventView()
	recorder.Record(ev.syscallName(), view.duration, view.ret)
}

func (ev syscallEventContext) updateFDOffsets(port fdOffsetUpdatePort) {
	if port == nil || !ev.shouldUpdateFDOffsets() {
		return
	}
	port.ApplyFDOffsets(ev.fdOffsetUpdate())
}

func (ev syscallEventContext) fdOffsetUpdate() fdOffsetUpdate {
	return fdOffsetUpdate{
		view:     ev.eventView(),
		meta:     ev.effectiveSyscallMeta(),
		statePID: ev.statePID,
	}
}

func (ev syscallEventContext) cleanupClosedFD(port fdCloseUpdatePort) {
	if port == nil || !ev.shouldCleanupClosedFD() {
		return
	}
	port.CleanupClosedFD(ev.fdCloseUpdate())
}

func (ev syscallEventContext) fdCloseUpdate() fdCloseUpdate {
	return fdCloseUpdate{
		view:     ev.eventView(),
		meta:     ev.effectiveSyscallMeta(),
		statePID: ev.statePID,
	}
}

func (ev syscallEventContext) updateFDState(port fdStateUpdatePort) {
	if port == nil {
		return
	}
	port.ApplyFDState(ev.fdStateUpdate())
}

func (ev syscallEventContext) fdStateUpdate() fdStateUpdate {
	view := ev.eventView()
	return fdStateUpdate{
		source: fdStateSource{
			view:            view,
			payloadSections: ev.outputPayloadSections(),
		},
		meta:        ev.effectiveSyscallMeta(),
		flagDecoder: ev.fdFlags,
		pathText:    ev.pathText,
		targetPID:   ev.statePID,
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

func (ev syscallEventContext) newHandlerContext(deps syscallEventContextDeps) *handler.Context {
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	context := deps.contextPool.acquire()
	if deps.contextPool == nil {
		applyHandlerContextSessionPorts(context, handlerContextSessionPortsFromDeps(deps))
	}
	context.Pid = int(view.pid)
	context.Tid = int(view.tid)
	context.TargetPid = ev.statePID
	context.SysId = view.sysID
	context.SysName = scMeta.Name
	context.Args = view.args
	context.Ret = view.ret
	context.ProbeRetEnter = view.probeRetEnter
	context.ProbeRetExit = view.probeRetExit
	context.PayloadSections = ev.outputPayloadSections()
	context.ScMeta = scMeta
	context.EventFDView = ev.handlerEventFDView()
	return context
}

func handlerContextSessionPortsFromDeps(deps syscallEventContextDeps) handlerContextSessionPorts {
	return handlerContextSessionPorts{
		meta:     deps.catalog,
		registry: deps.registry,
		dispatch: deps.handlerDispatch,
		decoder:  deps.decoder,
		opts:     deps.handlerOpts,
		fdState:  deps.fdStateReader(),
		runtime:  deps.runtimeService(),
	}
}

func (ev syscallEventContext) handlerEventFDView() handler.EventFDStateReader {
	if len(ev.eventFDView.paths) == 0 && len(ev.eventFDView.states) == 0 && ev.eventFDView.cwd == "" {
		return nil
	}
	return ev.eventFDView
}

func (ev syscallEventContext) releaseHandlerContext() {
	if ev.contextRecycler == nil {
		return
	}
	ev.contextRecycler.release(ev.handlerContext)
}

func (ev syscallEventContext) shouldOutput() bool {
	return ev.shouldPrint
}

func (ev syscallEventContext) shouldRunHandler() bool {
	return ev.shouldPrint || ev.isFDStateSyscall()
}

func (ev syscallEventContext) shouldUpdateFDState() bool {
	return shouldApplyFDStateEventWithTraits(
		ev.view,
		ev.payloadSections,
		ev.eventTraits(),
	)
}

func (ev syscallEventContext) shouldUpdateFDOffsets() bool {
	return shouldApplyFDOffsetEventWithTraits(ev.view, ev.eventTraits())
}

func (ev syscallEventContext) shouldCleanupClosedFD() bool {
	return shouldCleanupClosedFDEventWithTraits(ev.view, ev.eventTraits())
}

func (ev syscallEventContext) shouldEmitRawEnter(fdState event.FDPathReader) bool {
	if ev.filter == nil {
		return false
	}
	if ev.filter.DebugEvents() {
		return true
	}
	return checkShouldPrintFromView(printFilterRequest{
		view:          ev.eventView(),
		scMeta:        ev.effectiveSyscallMeta(),
		pathArguments: ev.pathArguments,
		targetPid:     ev.statePID,
		filter:        ev.filter,
		fdState:       fdState,
		eventFD:       ev.eventFDView,
	})
}

func (ev syscallEventContext) handleWith(handle func(string, *handler.Context) handler.Result) handler.Result {
	if ev.handlerContext != nil && ev.handlerContext.HandlerDispatch != nil {
		return ev.handlerContext.HandlerDispatch.Handle(
			ev.handlerContext.SysId,
			ev.syscallName(),
			ev.handlerContext,
		)
	}
	if handle == nil {
		return handler.Result{}
	}
	return handle(ev.syscallName(), ev.handlerContext)
}

func (ev syscallEventContext) isFDStateSyscall() bool {
	return ev.eventTraits()&syscallEventTraitHandler != 0
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
