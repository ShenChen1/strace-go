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
}

// newTraceSession creates the complete event pipeline before the first event
// is read. All session-owned dependencies must be explicit at this boundary.
func newTraceSession(deps traceSessionDeps) (*traceSession, error) {
	if err := validateTraceSessionDeps(deps); err != nil {
		return nil, err
	}
	session := &traceSession{
		cmd:           deps.Cmd,
		events:        deps.Events,
		targetPid:     deps.TargetPID,
		opts:          deps.Opts,
		catalog:       deps.Catalog,
		decoder:       deps.Decoder,
		fdState:       deps.FDState,
		runtime:       deps.Runtime,
		outWriter:     deps.OutWriter,
		output:        deps.Output,
		summary:       deps.Summary,
		timeFormatter: deps.TimeFormatter,
		bpfObjs:       deps.BPFObjects,
		resolver:      deps.Resolver,
		state:         deps.State,
		clock:         deps.Clock,
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
	handlerRegistry := handler.NewRegistry()
	handleSyscall := handlerRegistry.Handle
	return traceSessionBaseComponents{
		jsonWriter: newJSONEventWriter(JSONEventWriterDeps{Out: session.outWriter}),
		renderer: newTextRenderer(TextRendererDeps{
			Out:           session.outWriter,
			Opts:          session.opts,
			State:         session.state,
			TimeFormatter: session.timeFormatter,
			BPFObjs:       session.bpfObjs,
			Resolver:      session.resolver,
		}),
		exitStatus: newExitStatusCoordinator(ExitStatusCoordinatorDeps{
			Queue:      newExitStatusQueue(),
			Out:        session.outWriter,
			HasCommand: session.cmd != nil,
			AttachPids: attachPIDs(session.opts),
		}),
		handlerRegistry: handlerRegistry,
		handleSyscall:   handleSyscall,
		handlerRunner: newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
			HandleSyscall: handleSyscall,
			Effects:       newTraceSessionSyscallHandlerEffects(session.fdState),
		}),
	}
}

func buildTraceSessionOutputs(
	session *traceSession,
	base traceSessionBaseComponents,
) traceSessionOutputComponents {
	execOutput := newExecSyscallOutput(ExecSyscallOutputDeps{
		Opts:              session.opts,
		State:             session.state,
		Renderer:          base.renderer,
		DiscardExitStatus: base.exitStatus.Discard,
	})
	suspendedOutput := newSuspendedSyscallOutput(SuspendedSyscallOutputDeps{
		State:    session.state,
		Renderer: base.renderer,
	})
	syscallText := newSyscallTextOutput(SyscallTextOutputDeps{
		Opts:      session.opts,
		Suspended: suspendedOutput,
		Exec:      execOutput,
		Renderer:  base.renderer,
	})
	syscallJSON := newSyscallJSONOutput(SyscallJSONOutputDeps{
		Opts:    session.opts,
		FDState: session.fdStateStore(),
		Writer:  base.jsonWriter,
	})
	exitSyscall := newExitSyscallOutput(ExitSyscallOutputDeps{
		Opts:              session.opts,
		Renderer:          base.renderer,
		Out:               session.outWriter,
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
	exitPipeline := newSyscallExitPipeline(SyscallExitPipelineDeps{
		Opts:    session.opts,
		JSON:    outputs.syscallJSON,
		Exit:    outputs.exitSyscall,
		Runner:  base.handlerRunner,
		Text:    outputs.syscallText,
		Effects: newTraceSessionSyscallExitEffects(session.summary, session.fdState, session.fdState),
	})
	lifecycle := newLifecycleEventHandler(LifecycleEventHandlerDeps{
		Opts: session.opts,
		Effects: newTraceSessionLifecycleEffects(
			session.fdState,
			base.jsonWriter,
			session.writeLifecycleExitText,
		),
	})
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:       newTraceScope(session.targetPid, session.opts),
		TargetPID:   session.targetPid,
		State:       session.state,
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
	recordDecoder := traceRingbufRecordDecoder{}
	return traceSessionRuntimeComponents{
		recordDecoder: recordDecoder,
		eventReader: newTraceEventReader(TraceEventReaderDeps{
			Reader:  session.events,
			Decoder: recordDecoder,
			Sink:    router,
			Clock:   session.clock,
		}),
		runFinalizer: newTraceRunFinalizer(TraceRunFinalizerDeps{
			Opts:            session.opts,
			TargetPID:       session.targetPid,
			StatsDiagnostic: os.Stderr,
			ExitStatus:      exitStatus,
			Summary:         session.summary,
			BPFObjects:      session.bpfObjs,
			Output:          session.output,
		}),
		commandExitHandler: newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
			Opts:       session.opts,
			TargetPID:  session.targetPid,
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
