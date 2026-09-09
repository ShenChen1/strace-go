package main

import (
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

var _ handler.SnapshotDecoder = (*event.Decoder)(nil)

type syscallEventContext struct {
	view                 syscallEventView
	statePID             int
	meta                 meta.Syscall
	traits               syscallEventTraits
	traitsBound          bool
	fdFlags              fdFlagDecoder
	filter               traceFilterOptions
	pathText             string
	pathArguments        []event.PathArgument
	shouldPrint          bool
	pendingEnter         *pendingSyscallSnapshot
	handlerContext       *handler.Context
	contextRecycler      *handlerContextRecycler
	payloadSections      []handler.PayloadSection
	eventFDView          eventFDStateView
	detached             bool
	detachedByStatus     bool
	detachedByExecPolicy bool
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
	cpuDuration   uint64
	enterTime     uint64
	stackID       int32
	kvmExitReason uint32
	probeRetEnter int32
	probeRetExit  int32
	comm          string
}

type syscallEventContextDeps struct {
	decoder           handler.SnapshotDecoder
	handlerOpts       handler.OptionsPort
	filter            traceFilterOptions
	catalog           meta.CatalogPort
	syscallMetadata   *syscallMetadataTable
	handlerDecodePlan *syscallDecodePlan
	fdState           handler.FDStateReader
	fdPath            event.FDPathReader
	registry          handler.RegistryPort
	handlerDispatch   handler.HandlerDispatchPort
	runtime           handler.RuntimeServices
	contextPool       *handlerContextRecycler
}

type syscallEventContextDependencySource interface {
	eventContextDependencies() syscallEventContextDeps
}

type traceSummaryRecorder interface {
	Record(name string, cpuDuration, wallDuration uint64, ret int64)
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
	scMeta, traits, traitsBound := lookupSyscallMetadataWithTraits(deps.syscallMetadata, view)
	if canUseFastSyscallEventContext(view, pendingEnter, currentPayload, deps.filter) {
		ev := syscallEventContext{
			view:            view,
			statePID:        statePID,
			meta:            scMeta,
			traits:          traits,
			traitsBound:     traitsBound,
			fdFlags:         deps.catalog,
			filter:          deps.filter,
			shouldPrint:     true,
			pendingEnter:    pendingEnter,
			contextRecycler: deps.contextPool,
		}
		if shouldBuildHandlerContext(ev, deps) {
			ev.handlerContext = ev.newHandlerContext(deps)
		}
		return ev
	}
	payloadSections := mergePendingPayloadSections(pendingEnter, currentPayload)
	eventFDView := eventFDViewFromSections(scMeta.Name, view, payloadSections)
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
		traits:          traits,
		traitsBound:     traitsBound,
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
	if shouldBuildHandlerContext(ev, deps) {
		ev.handlerContext = ev.newHandlerContext(deps)
	}
	return ev
}

func shouldBuildHandlerContext(ev syscallEventContext, deps syscallEventContextDeps) bool {
	if !ev.shouldRunHandler() {
		return false
	}
	if len(ev.outputPayloadSections()) > 0 {
		return true
	}
	if handlerContextNeededForReturn(ev, deps.handlerOpts) {
		return true
	}
	return deps.handlerDecodePlan.needs(ev.view.sysID, ev.syscallName())
}

func handlerContextNeededForReturn(ev syscallEventContext, opts handler.OptionsPort) bool {
	if opts == nil || !opts.ShowPathsValue() {
		return false
	}
	name := ev.syscallName()
	if isFdReturnSyscall(name) {
		return true
	}
	return isFcntlFDStateSyscall(name) && isFcntlFDStateCommand(ev.view.args)
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
	if pendingEnter.payloadStorage != nil {
		merged := pendingEnter.payloadStorage.mergeView(current)
		pendingEnter.payloadSections = merged
		return merged
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
	scMeta, traits, traitsBound := lookupSyscallMetadataWithTraits(config.syscallMetadata, config.view)
	fdPathOverlay := fdPathOverlayFromSections(config.payloadSections)
	eventFDView := fdPathOverlay.resolve(config.view)
	return syscallEventContext{
		view:            config.view,
		statePID:        config.statePID,
		meta:            scMeta,
		traits:          traits,
		traitsBound:     traitsBound,
		fdFlags:         config.flagDecoder,
		filter:          config.filter,
		payloadSections: config.payloadSections,
		eventFDView:     eventFDView,
	}
}
