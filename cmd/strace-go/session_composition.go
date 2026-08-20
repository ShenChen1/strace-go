package main

import (
	"fmt"
	"io"
	"os"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

// traceSessionComponents is the composition root for one tracing session.
// Components are constructed once, in dependency order, and never replace
// each other during event processing.
type traceSessionComponents struct {
	debugPhases        traceDebugPhasePort
	textRenderer       *TextRenderer
	jsonWriter         *JSONEventWriter
	syscallJSON        *SyscallJSONOutput
	syscallText        *SyscallTextOutput
	exitSyscall        *ExitSyscallOutput
	handlerRunner      *SyscallHandlerRunner
	handlerRegistry    *handler.Registry
	handlerDispatch    handler.HandlerDispatchPort
	exitPipeline       *SyscallExitPipeline
	lifecycleHandler   *LifecycleEventHandler
	exitStatus         *ExitStatusCoordinator
	eventRouter        *TraceEventRouter
	recordDecoder      traceRecordDecoder
	eventReader        *TraceEventReader
	runFinalizer       *TraceRunFinalizer
	commandExitHandler *TraceCommandExitHandler
}

type traceSessionBaseComponents struct {
	jsonWriter      *JSONEventWriter
	debugPhases     traceDebugPhasePort
	renderer        *TextRenderer
	exitStatus      *ExitStatusCoordinator
	outputPolicy    traceOutputPolicyOwner
	handlerRegistry *handler.Registry
	handleSyscall   func(string, *handler.Context) handler.Result
	handlerRunner   *SyscallHandlerRunner
}

type traceSessionOutputComponents struct {
	syscallJSON *SyscallJSONOutput
	syscallText *SyscallTextOutput
	exitSyscall *ExitSyscallOutput
}

type traceSessionEventComponents struct {
	exitPipeline     *SyscallExitPipeline
	lifecycleHandler *LifecycleEventHandler
	eventRouter      *TraceEventRouter
}

type traceSessionBootstrap struct {
	hasCommand    bool
	commandWaiter traceCommandWaiter
	events        traceRingbufReader
	targetPID     int
	fdSeed        fdStateSeed
	bpfReads      traceBPFReadPorts
}

func composeTraceSession(
	config traceSessionConfig,
	clock traceClock,
	bootstrap traceSessionBootstrap,
	output *TraceOutput,
) (*traceSession, error) {
	state := newTraceStateForSession(config.eventPolicy)
	state.setCommandTargetPID(bootstrap.targetPID)
	if config.outputPolicy != nil {
		state.seedAttachTargets(config.outputPolicy.AttachPIDs())
	}
	state.setAttachExitReader(bootstrap.bpfReads.AttachExits)
	return newTraceSession(traceSessionDeps{
		HasCommand:    bootstrap.hasCommand,
		CommandWaiter: bootstrap.commandWaiter,
		Events:        bootstrap.events,
		TargetPID:     bootstrap.targetPID,
		EventPolicy:   config.eventPolicy,
		OutputPolicy:  config.outputPolicy,
		Catalog:       config.catalog,
		Decoder:       config.decoder,
		FDState:       newFDStateStoreFromSeed(bootstrap.fdSeed),
		Runtime:       handler.NewRuntime(),
		OutWriter:     output,
		Output:        output,
		Summary:       newSummaryStats(),
		TimeFormatter: newTimeFormatterWithClock(calculateTimeOffsetWithClock(clock), clock),
		StackTraces:   bootstrap.bpfReads.StackTraces,
		Stats:         bootstrap.bpfReads.Stats,
		Resolver:      config.resolver,
		State:         state,
		Clock:         clock,
	})
}

// traceSessionDeps contains external resources and immutable session policy.
// CLI parsing and policy construction stay outside this runtime graph.
type traceSessionDeps struct {
	HasCommand    bool
	CommandWaiter traceCommandWaiter
	Events        traceRingbufReader
	TargetPID     int
	EventPolicy   traceEventPolicyOwner
	OutputPolicy  traceOutputPolicyOwner
	Catalog       meta.CatalogPort
	Decoder       handler.SnapshotDecoder
	FDState       traceFDStateOwner
	Runtime       handler.RuntimeServices
	OutWriter     io.Writer
	Output        traceFinalizerOutput
	Summary       traceSummaryOwner
	TimeFormatter traceTimeFormatter
	StackTraces   traceStackTraceReader
	Stats         traceStatsReader
	Resolver      traceSymbolResolver
	State         traceStateOwner
	Clock         traceClock
}

// newTraceSession creates the complete event pipeline before the first event
// is read. All session-owned dependencies must be explicit at this boundary.
func newTraceSession(deps traceSessionDeps) (*traceSession, error) {
	if err := validateTraceSessionDeps(deps); err != nil {
		return nil, err
	}
	session := &traceSession{
		dependencies: deps,
	}
	session.components = buildTraceSessionComponents(deps)
	return session, nil
}

func validateTraceSessionDeps(deps traceSessionDeps) error {
	if deps.HasCommand != (deps.CommandWaiter != nil) {
		return fmt.Errorf("trace command lifecycle dependencies are inconsistent")
	}
	missing := []struct {
		name  string
		isNil bool
	}{
		{name: "Events", isNil: deps.Events == nil},
		{name: "EventPolicy", isNil: deps.EventPolicy == nil},
		{name: "OutputPolicy", isNil: deps.OutputPolicy == nil},
		{name: "Catalog", isNil: deps.Catalog == nil},
		{name: "Decoder", isNil: deps.Decoder == nil},
		{name: "FDState", isNil: deps.FDState == nil},
		{name: "Runtime", isNil: deps.Runtime == nil},
		{name: "OutWriter", isNil: deps.OutWriter == nil},
		{name: "Summary", isNil: deps.Summary == nil},
		{name: "TimeFormatter", isNil: deps.TimeFormatter == nil},
		{name: "State", isNil: deps.State == nil},
		{name: "Clock", isNil: deps.Clock == nil},
	}
	for _, dependency := range missing {
		if dependency.isNil {
			return fmt.Errorf("trace session dependency %s is nil", dependency.name)
		}
	}
	return nil
}

func newTraceStateForSession(policy traceStatePolicy) *TraceState {
	trackForkIdentity := true
	deferUnmatchedExits := false
	if policy != nil {
		trackForkIdentity = policy.TrackForkIdentity()
		deferUnmatchedExits = policy.ShouldDeferUnmatchedExits()
	}
	return &TraceState{
		deferUnmatchedExits: deferUnmatchedExits,
		trackForkIdentity:   trackForkIdentity,
		unfinishedEnabled:   true,
		lifecycleIDs:        newSyscallLifecycleIDs(meta.SyscallTable),
	}
}

func buildTraceSessionComponents(
	deps traceSessionDeps,
) *traceSessionComponents {
	base := buildTraceSessionBase(deps)
	outputs := buildTraceSessionOutputs(deps, base)
	handlerDispatch := handler.NewDispatchTable(base.handlerRegistry, meta.SyscallTable)
	contextDeps := deps.eventContextDependencies(base.handlerRegistry)
	contextDeps.handlerDispatch = handlerDispatch
	events := buildTraceSessionEvents(
		deps,
		base,
		outputs,
		contextDeps,
	)
	runtime := buildTraceSessionRuntime(deps, base, events.eventRouter)
	return &traceSessionComponents{
		debugPhases:        base.debugPhases,
		textRenderer:       base.renderer,
		jsonWriter:         base.jsonWriter,
		syscallJSON:        outputs.syscallJSON,
		syscallText:        outputs.syscallText,
		exitSyscall:        outputs.exitSyscall,
		handlerRunner:      base.handlerRunner,
		handlerRegistry:    base.handlerRegistry,
		handlerDispatch:    handlerDispatch,
		exitPipeline:       events.exitPipeline,
		lifecycleHandler:   events.lifecycleHandler,
		exitStatus:         base.exitStatus,
		eventRouter:        events.eventRouter,
		recordDecoder:      runtime.recordDecoder,
		eventReader:        runtime.eventReader,
		runFinalizer:       runtime.runFinalizer,
		commandExitHandler: runtime.commandExitHandler,
	}
}

func buildTraceSessionBase(deps traceSessionDeps) traceSessionBaseComponents {
	handlerRegistry := handler.NewRegistry()
	handleSyscall := defaultHandleSyscall
	outputPolicy := deps.OutputPolicy
	jsonWriter := newJSONEventWriter(JSONEventWriterDeps{Out: deps.OutWriter})
	return traceSessionBaseComponents{
		jsonWriter:   jsonWriter,
		debugPhases:  newTraceDebugPhaseWriter(outputPolicy, jsonWriter, deps.Clock),
		outputPolicy: outputPolicy,
		renderer: newTextRenderer(TextRendererDeps{
			Out:           deps.OutWriter,
			Policy:        outputPolicy,
			State:         deps.State,
			TimeFormatter: deps.TimeFormatter,
			StackTraces:   deps.StackTraces,
			Resolver:      deps.Resolver,
		}),
		exitStatus: newExitStatusCoordinator(ExitStatusCoordinatorDeps{
			Queue:      newExitStatusQueue(),
			Out:        deps.OutWriter,
			HasCommand: deps.HasCommand,
			AttachPids: outputPolicy.AttachPIDs(),
		}),
		handlerRegistry: handlerRegistry,
		handleSyscall:   handleSyscall,
		handlerRunner: newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
			HandleSyscall: handleSyscall,
			Effects:       newTraceSessionSyscallHandlerEffects(deps.FDState),
		}),
	}
}

func buildTraceSessionOutputs(
	deps traceSessionDeps,
	base traceSessionBaseComponents,
) traceSessionOutputComponents {
	execOutput := newExecSyscallOutput(ExecSyscallOutputDeps{
		Policy:            base.outputPolicy,
		State:             deps.State,
		Renderer:          base.renderer,
		DiscardExitStatus: base.exitStatus.Discard,
	})
	suspendedOutput := newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{
		State:    deps.State,
		Renderer: base.renderer,
	})
	syscallText := newSyscallTextOutput(SyscallTextOutputDeps{
		Format:    base.outputPolicy,
		Policy:    base.outputPolicy,
		Suspended: suspendedOutput,
		Exec:      execOutput,
		Renderer:  base.renderer,
	})
	syscallJSON := newSyscallJSONOutput(SyscallJSONOutputDeps{
		Format:  base.outputPolicy,
		Policy:  base.outputPolicy,
		FDState: deps.FDState,
		Writer:  base.jsonWriter,
	})
	exitSyscall := newExitSyscallOutput(ExitSyscallOutputDeps{
		Policy:            base.outputPolicy,
		Renderer:          base.renderer,
		Out:               deps.OutWriter,
		HandleSyscall:     base.handleSyscall,
		ShouldQueueStatus: base.exitStatus.ShouldQueue,
		QueueStatus:       base.exitStatus.Queue,
		JSONWriter:        base.jsonWriter,
	})
	return traceSessionOutputComponents{
		syscallJSON: syscallJSON,
		syscallText: syscallText,
		exitSyscall: exitSyscall,
	}
}

func buildTraceSessionEvents(
	deps traceSessionDeps,
	base traceSessionBaseComponents,
	outputs traceSessionOutputComponents,
	contextDeps syscallEventContextDeps,
) traceSessionEventComponents {
	var exitPipeline *SyscallExitPipeline
	var lifecycle *LifecycleEventHandler
	var exitSink syscallExitSink
	var lifecycleSink lifecycleEventSink
	var jsonSink syscallEnterSink
	if !base.outputPolicy.DiscardEvents() || isTraceHandlerOnlyPolicy(base.outputPolicy) {
		contextDeps.contextPool = newHandlerContextRecycler()
		exitPipeline = newSyscallExitPipeline(SyscallExitPipelineDeps{
			Summary: base.outputPolicy,
			JSON:    outputs.syscallJSON,
			Exit:    outputs.exitSyscall,
			Runner:  base.handlerRunner,
			Text:    outputs.syscallText,
			Effects: newTraceSessionSyscallExitEffects(deps.Summary, deps.FDState, deps.FDState),
		})
		lifecycle = newLifecycleEventHandler(LifecycleEventHandlerDeps{
			Policy: base.outputPolicy,
			Effects: newTraceSessionLifecycleEffects(
				deps.FDState,
				base.jsonWriter,
				newTraceLifecycleExitTextWriter(traceLifecycleExitTextWriterDeps{
					Policy:     deps.OutputPolicy,
					HasCommand: deps.HasCommand,
					TargetPID:  deps.TargetPID,
					Out:        deps.OutWriter,
					Renderer:   base.renderer,
				}),
			),
		})
		exitSink = exitPipeline
		lifecycleSink = lifecycle
		jsonSink = outputs.syscallJSON
	}
	deps.State.setUnfinishedEnabled(outputs.syscallText.textMode())
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:       newTraceScope(deps.TargetPID, base.outputPolicy),
		TargetPID:   deps.TargetPID,
		State:       deps.State,
		Lifecycle:   lifecycleSink,
		JSON:        jsonSink,
		Pipeline:    exitSink,
		ContextDeps: contextDeps,
	})
	return traceSessionEventComponents{
		exitPipeline:     exitPipeline,
		lifecycleHandler: lifecycle,
		eventRouter:      router,
	}
}

type traceSessionRuntimeComponents struct {
	recordDecoder      traceRecordDecoder
	eventReader        *TraceEventReader
	runFinalizer       *TraceRunFinalizer
	commandExitHandler *TraceCommandExitHandler
}

func buildTraceSessionRuntime(
	deps traceSessionDeps,
	base traceSessionBaseComponents,
	router *TraceEventRouter,
) traceSessionRuntimeComponents {
	var recordDecoder traceRecordDecoder = traceRingbufRecordDecoder{}
	var eventSink traceEventSink = router
	if isTraceReaderOnlyPolicy(base.outputPolicy) {
		recordDecoder = traceRingbufBoundaryDecoder{}
		eventSink = nil
	}
	eventReader := newTraceEventReader(TraceEventReaderDeps{
		Reader:            deps.Events,
		Decoder:           recordDecoder,
		Sink:              eventSink,
		Clock:             deps.Clock,
		MeasureService:    base.outputPolicy.DebugPhases(),
		ServiceSampleRate: traceDiagnosticServiceSampleRate,
	})
	return traceSessionRuntimeComponents{
		recordDecoder: recordDecoder,
		eventReader:   eventReader,
		runFinalizer: newTraceRunFinalizer(TraceRunFinalizerDeps{
			FormatPolicy:    base.outputPolicy,
			SummaryPolicy:   base.outputPolicy,
			TargetPID:       deps.TargetPID,
			StatsDiagnostic: os.Stderr,
			ExitStatus:      base.exitStatus,
			Summary:         deps.Summary,
			Stats:           deps.Stats,
			ReaderStats:     eventReader,
			PendingState:    deps.State,
			DebugPhases:     base.debugPhases,
			Output:          deps.Output,
		}),
		commandExitHandler: newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
			Policy:     base.outputPolicy,
			TargetPID:  deps.TargetPID,
			ExitStatus: base.exitStatus,
			Renderer:   base.renderer,
		}),
	}
}
