package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
	"strace-go/pkg/stacktrace"
)

// traceSessionComponents is the composition root for one tracing session.
// Components are constructed once, in dependency order, and never replace
// each other during event processing.
type traceSessionComponents struct {
	eventPolicy        *cliTraceEventPolicy
	outputPolicy       *cliTraceOutputPolicy
	textRenderer       *TextRenderer
	jsonWriter         *JSONEventWriter
	syscallJSON        *SyscallJSONOutput
	syscallText        *SyscallTextOutput
	exitSyscall        *ExitSyscallOutput
	handlerRunner      *SyscallHandlerRunner
	handlerRegistry    *handler.Registry
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
	eventPolicy     *cliTraceEventPolicy
	jsonWriter      *JSONEventWriter
	renderer        *TextRenderer
	exitStatus      *ExitStatusCoordinator
	outputPolicy    *cliTraceOutputPolicy
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

// traceSessionDeps contains external resources and immutable session policy.
// CLI parsing and policy construction stay outside this runtime graph.
type traceSessionDeps struct {
	Cmd           *exec.Cmd
	Events        traceRingbufReader
	TargetPID     int
	EventPolicy   *cliTraceEventPolicy
	OutputPolicy  *cliTraceOutputPolicy
	Catalog       *meta.Catalog
	Decoder       *event.Decoder
	FDState       *FDStateStore
	Runtime       handler.RuntimeServices
	OutWriter     io.Writer
	Output        *TraceOutput
	Summary       *SummaryStats
	TimeFormatter *TimeFormatter
	BPFObjects    *bpfObjects
	Resolver      *stacktrace.Resolver
	State         *TraceState
	Clock         traceClock
	PIDProbe      tracePIDProbe
}

// newTraceSession creates the complete event pipeline before the first event
// is read. All session-owned dependencies must be explicit at this boundary.
func newTraceSession(deps traceSessionDeps) (*traceSession, error) {
	if err := validateTraceSessionDeps(deps); err != nil {
		return nil, err
	}
	session := &traceSession{
		dependencies: deps,
		eventPolicy:  deps.EventPolicy,
	}
	session.components = buildTraceSessionComponents(session)
	return session, nil
}

func validateTraceSessionDeps(deps traceSessionDeps) error {
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
		{name: "PIDProbe", isNil: deps.PIDProbe == nil},
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
	}
}

func buildTraceSessionComponents(session *traceSession) *traceSessionComponents {
	base := buildTraceSessionBase(session)
	outputs := buildTraceSessionOutputs(session, base)
	events := buildTraceSessionEvents(session, base, outputs)
	runtime := buildTraceSessionRuntime(session, base.outputPolicy, base.exitStatus, base.renderer, events.eventRouter)
	return &traceSessionComponents{
		eventPolicy:        base.eventPolicy,
		outputPolicy:       base.outputPolicy,
		textRenderer:       base.renderer,
		jsonWriter:         base.jsonWriter,
		syscallJSON:        outputs.syscallJSON,
		syscallText:        outputs.syscallText,
		exitSyscall:        outputs.exitSyscall,
		handlerRunner:      base.handlerRunner,
		handlerRegistry:    base.handlerRegistry,
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

func buildTraceSessionBase(session *traceSession) traceSessionBaseComponents {
	deps := session.dependencies
	handlerRegistry := handler.NewRegistry()
	handleSyscall := handlerRegistry.Handle
	eventPolicy := session.eventPolicy
	outputPolicy := deps.OutputPolicy
	return traceSessionBaseComponents{
		eventPolicy:  eventPolicy,
		jsonWriter:   newJSONEventWriter(JSONEventWriterDeps{Out: deps.OutWriter}),
		outputPolicy: outputPolicy,
		renderer: newTextRenderer(TextRendererDeps{
			Out:           deps.OutWriter,
			Policy:        outputPolicy,
			State:         deps.State,
			TimeFormatter: deps.TimeFormatter,
			BPFObjs:       deps.BPFObjects,
			Resolver:      deps.Resolver,
		}),
		exitStatus: newExitStatusCoordinator(ExitStatusCoordinatorDeps{
			Queue:      newExitStatusQueue(),
			Out:        deps.OutWriter,
			HasCommand: deps.Cmd != nil,
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
	session *traceSession,
	base traceSessionBaseComponents,
) traceSessionOutputComponents {
	deps := session.dependencies
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
	session *traceSession,
	base traceSessionBaseComponents,
	outputs traceSessionOutputComponents,
) traceSessionEventComponents {
	deps := session.dependencies
	exitPipeline := newSyscallExitPipeline(SyscallExitPipelineDeps{
		Summary: base.outputPolicy,
		JSON:    outputs.syscallJSON,
		Exit:    outputs.exitSyscall,
		Runner:  base.handlerRunner,
		Text:    outputs.syscallText,
		Effects: newTraceSessionSyscallExitEffects(deps.Summary, deps.FDState, deps.FDState),
	})
	lifecycle := newLifecycleEventHandler(LifecycleEventHandlerDeps{
		Policy: base.outputPolicy,
		Effects: newTraceSessionLifecycleEffects(
			deps.FDState,
			base.jsonWriter,
			session.writeLifecycleExitText,
		),
	})
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:       newTraceScope(deps.TargetPID, base.outputPolicy),
		TargetPID:   deps.TargetPID,
		State:       deps.State,
		Lifecycle:   lifecycle,
		JSON:        outputs.syscallJSON,
		Pipeline:    exitPipeline,
		ContextDeps: newSyscallEventContextDepsWithPolicy(session, base.handlerRegistry, base.eventPolicy),
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
	session *traceSession,
	outputPolicy *cliTraceOutputPolicy,
	exitStatus *ExitStatusCoordinator,
	renderer *TextRenderer,
	router *TraceEventRouter,
) traceSessionRuntimeComponents {
	deps := session.dependencies
	recordDecoder := traceRingbufRecordDecoder{}
	return traceSessionRuntimeComponents{
		recordDecoder: recordDecoder,
		eventReader: newTraceEventReader(TraceEventReaderDeps{
			Reader:  deps.Events,
			Decoder: recordDecoder,
			Sink:    router,
			Clock:   deps.Clock,
		}),
		runFinalizer: newTraceRunFinalizer(TraceRunFinalizerDeps{
			FormatPolicy:    outputPolicy,
			SummaryPolicy:   outputPolicy,
			TargetPID:       deps.TargetPID,
			StatsDiagnostic: os.Stderr,
			ExitStatus:      exitStatus,
			Summary:         deps.Summary,
			BPFObjects:      deps.BPFObjects,
			Output:          deps.Output,
		}),
		commandExitHandler: newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
			Policy:     outputPolicy,
			TargetPID:  deps.TargetPID,
			ExitStatus: exitStatus,
			Renderer:   renderer,
		}),
	}
}

func attachPIDs(opts *cli.Options) []int {
	if opts == nil {
		return nil
	}
	return opts.AttachPids
}
