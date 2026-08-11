package main

import (
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
	OutWriter     io.Writer
	Output        *TraceOutput
	TimeFormatter *TimeFormatter
	BPFObjects    *bpfObjects
	Resolver      *stacktrace.Resolver
	State         *TraceState
}

// newTraceSession creates the complete event pipeline before the first event
// is read. Zero-valued dependencies are normalized to safe session defaults.
func newTraceSession(deps traceSessionDeps) *traceSession {
	session := &traceSession{
		cmd:           deps.Cmd,
		events:        deps.Events,
		targetPid:     deps.TargetPID,
		opts:          deps.Opts,
		catalog:       deps.Catalog,
		decoder:       deps.Decoder,
		fdState:       deps.FDState,
		outWriter:     deps.OutWriter,
		output:        deps.Output,
		timeFormatter: deps.TimeFormatter,
		bpfObjs:       deps.BPFObjects,
		resolver:      deps.Resolver,
		state:         deps.State,
	}
	if session.state == nil {
		session.state = newTraceStateWithDeferredExit(shouldEmitGenericEnter(session.opts))
	}
	normalizeTraceSession(session)
	session.components = buildTraceSessionComponents(session)
	return session
}

func normalizeTraceSession(session *traceSession) {
	if session.catalog == nil {
		format := "abbrev"
		if session.opts != nil {
			format = session.opts.XlatFormat
		}
		session.catalog = meta.NewCatalog(format)
	}
	if session.decoder == nil {
		session.decoder = event.NewDecoder()
	}
	if session.fdState == nil {
		session.fdState = newFDStateStoreFromMaps(nil, nil)
	}
	if session.outWriter == nil {
		session.outWriter = io.Discard
	}
	if session.timeFormatter == nil {
		session.timeFormatter = newTimeFormatter(0)
	}
	if session.summary == nil {
		session.summary = newSummaryStats()
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
		PathMap: session.fdState.PathMap(),
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
		Effects: newTraceSessionSyscallExitEffects(session.summary, session.fdState),
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

func (s *traceSession) componentsOrBuild() *traceSessionComponents {
	if s == nil {
		return nil
	}
	if s.components == nil {
		if s.state == nil {
			// Hand-built event fixtures intentionally use immediate unmatched-exit
			// handling; production sessions are created by newTraceSession.
			s.state = newTraceState()
		}
		normalizeTraceSession(s)
		s.components = buildTraceSessionComponents(s)
	}
	return s.components
}
