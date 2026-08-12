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
	jsonWriter      *JSONEventWriter
	renderer        *TextRenderer
	exitStatus      *ExitStatusCoordinator
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

// traceSessionDeps contains external resources and session policy. Keeping
// construction inputs in one object makes ownership and test substitution
// visible without exporting the runtime graph.
type traceSessionDeps struct {
	Cmd           *exec.Cmd
	Events        traceRingbufReader
	TargetPID     int
	Opts          *cli.Options
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
		{name: "Opts", isNil: deps.Opts == nil},
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

func newTraceStateForSession(opts *cli.Options) *TraceState {
	trackForkIdentity := true
	if opts != nil {
		trackForkIdentity = opts.FollowForks
	}
	return &TraceState{
		deferUnmatchedExits: shouldEmitGenericEnter(opts),
		trackForkIdentity:   trackForkIdentity,
		unfinishedEnabled:   true,
	}
}

func buildTraceSessionComponents(session *traceSession) *traceSessionComponents {
	base := buildTraceSessionBase(session)
	outputs := buildTraceSessionOutputs(session, base)
	events := buildTraceSessionEvents(session, base, outputs)
	runtime := buildTraceSessionRuntime(session, base.exitStatus, base.renderer, events.eventRouter)
	return &traceSessionComponents{
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
	return traceSessionBaseComponents{
		jsonWriter: newJSONEventWriter(JSONEventWriterDeps{Out: deps.OutWriter}),
		renderer: newTextRenderer(TextRendererDeps{
			Out:           deps.OutWriter,
			Opts:          deps.Opts,
			State:         deps.State,
			TimeFormatter: deps.TimeFormatter,
			BPFObjs:       deps.BPFObjects,
			Resolver:      deps.Resolver,
		}),
		exitStatus: newExitStatusCoordinator(ExitStatusCoordinatorDeps{
			Queue:      newExitStatusQueue(),
			Out:        deps.OutWriter,
			HasCommand: deps.Cmd != nil,
			AttachPids: attachPIDs(deps.Opts),
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
		Opts:              deps.Opts,
		State:             deps.State,
		Renderer:          base.renderer,
		DiscardExitStatus: base.exitStatus.Discard,
	})
	suspendedOutput := newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{
		State:    deps.State,
		Renderer: base.renderer,
	})
	syscallText := newSyscallTextOutput(SyscallTextOutputDeps{
		Opts:      deps.Opts,
		Suspended: suspendedOutput,
		Exec:      execOutput,
		Renderer:  base.renderer,
	})
	syscallJSON := newSyscallJSONOutput(SyscallJSONOutputDeps{
		Opts:    deps.Opts,
		FDState: deps.FDState,
		Writer:  base.jsonWriter,
	})
	exitSyscall := newExitSyscallOutput(ExitSyscallOutputDeps{
		Opts:              deps.Opts,
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
		Opts:    deps.Opts,
		JSON:    outputs.syscallJSON,
		Exit:    outputs.exitSyscall,
		Runner:  base.handlerRunner,
		Text:    outputs.syscallText,
		Effects: newTraceSessionSyscallExitEffects(deps.Summary, deps.FDState, deps.FDState),
	})
	lifecycle := newLifecycleEventHandler(LifecycleEventHandlerDeps{
		Opts: deps.Opts,
		Effects: newTraceSessionLifecycleEffects(
			deps.FDState,
			base.jsonWriter,
			session.writeLifecycleExitText,
		),
	})
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:       newTraceScope(deps.TargetPID, deps.Opts),
		TargetPID:   deps.TargetPID,
		State:       deps.State,
		Lifecycle:   lifecycle,
		JSON:        outputs.syscallJSON,
		Pipeline:    exitPipeline,
		ContextDeps: newSyscallEventContextDepsWithRegistry(session, base.handlerRegistry),
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
			Opts:            deps.Opts,
			TargetPID:       deps.TargetPID,
			StatsDiagnostic: os.Stderr,
			ExitStatus:      exitStatus,
			Summary:         deps.Summary,
			BPFObjects:      deps.BPFObjects,
			Output:          deps.Output,
		}),
		commandExitHandler: newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
			Opts:       deps.Opts,
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
