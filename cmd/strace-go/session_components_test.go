package main

import (
	"bytes"
	"testing"
	"time"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

type sessionRegistryProbeHandler struct{}

func (sessionRegistryProbeHandler) Handle(*handler.Context) handler.Result {
	return handler.Result{ReturnDesc: "session-registry"}
}

func TestNewTraceSessionEagerlyComposesEventGraph(t *testing.T) {
	var output bytes.Buffer
	ringReader := &fakeRingbufReader{}
	state := newTraceStateWithDeferredExit(true)
	clock := &fakeTraceClock{now: time.Unix(300, 0)}
	session := newTraceSession(traceSessionDeps{
		Events:    ringReader,
		TargetPID: 101,
		Opts:      &cli.Options{EventFormat: cli.EventFormatJSON},
		OutWriter: &output,
		State:     state,
		Clock:     clock,
	})

	if session.components == nil {
		t.Fatal("newTraceSession() left components nil")
	}
	components := session.components
	if components.eventReader == nil || components.eventRouter == nil || components.recordDecoder == nil {
		t.Fatalf("event graph = %+v, want reader/router/decoder", components)
	}
	if components.handlerRegistry == nil || components.handlerRunner == nil {
		t.Fatal("event graph is missing the session handler registry")
	}
	if components.eventRouter.contextDeps.registry != components.handlerRegistry {
		t.Fatal("event router does not use the session handler registry")
	}
	if components.exitSyscall.handleSyscall == nil {
		t.Fatal("exit syscall output is missing the session handler resolver")
	}
	components.handlerRegistry.Register("session_registry_probe", sessionRegistryProbeHandler{})
	probeContext := &handler.Context{Registry: components.handlerRegistry}
	if got := components.handlerRunner.handleSyscall("session_registry_probe", probeContext); got.ReturnDesc != "session-registry" {
		t.Fatalf("runner resolver result = %+v, want session handler", got)
	}
	if got := components.exitSyscall.handleSyscall("session_registry_probe", probeContext); got.ReturnDesc != "session-registry" {
		t.Fatalf("exit resolver result = %+v, want session handler", got)
	}
	if components.eventReader.reader != ringReader {
		t.Fatal("event reader did not receive the injected ringbuf port")
	}
	if components.eventReader.decoder != components.recordDecoder {
		t.Fatal("event reader and session graph use different decoders")
	}
	if components.eventReader.sink != components.eventRouter {
		t.Fatal("event reader and session graph use different sinks")
	}
	if components.eventReader.clock != clock || session.clock != clock {
		t.Fatal("session and event reader do not share the injected clock")
	}
	runState := newTraceRunState(traceRunStateDeps{clock: session.clock})
	if runState.clock != clock {
		t.Fatal("run state does not use the session clock")
	}
	if components.eventRouter.state != state {
		t.Fatal("event router did not receive the session state")
	}
	if session.traceEventReader() != components.eventReader || session.traceEventRouter() != components.eventRouter {
		t.Fatal("component accessors replaced eagerly composed instances")
	}
	if got := session.traceState(); got != state || !got.deferUnmatchedExits {
		t.Fatalf("session state = %+v, want injected deferred state", got)
	}
}

func TestTraceSessionEagerGraphUsesOneExitStatusCoordinator(t *testing.T) {
	session := newTraceSession(traceSessionDeps{Opts: &cli.Options{}})
	components := session.components

	if components.exitStatus == nil || components.exitSyscall == nil || components.runFinalizer == nil {
		t.Fatalf("exit graph = %+v, want status/output/finalizer", components)
	}
	if components.exitSyscall.shouldQueueStatus == nil || components.exitSyscall.queueStatus == nil {
		t.Fatal("exit syscall output is missing status queue ports")
	}
	if components.runFinalizer.exitStatus != components.exitStatus {
		t.Fatal("finalizer does not share session exit status coordinator")
	}
	if components.commandExitHandler.exitStatus != components.exitStatus {
		t.Fatal("command exit handler does not share session exit status coordinator")
	}
}

var _ traceRingbufReader = (*fakeRingbufReader)(nil)
var _ traceRecordDecoder = traceRingbufRecordDecoder{}
var _ traceEventSink = (*TraceEventRouter)(nil)
var _ traceEventSink = (*recordingEventSink)(nil)

func TestTraceSessionFixtureUsesOneComposedComponentGraph(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{
		opts:      &cli.Options{},
		outWriter: &output,
	}

	if session.textRenderer() != session.textRenderer() {
		t.Fatal("textRenderer should be stable per session")
	}
	if session.syscallJSONOutput() != session.syscallJSONOutput() {
		t.Fatal("syscallJSONOutput should be stable per session")
	}
	if session.jsonEventWriter() != session.jsonEventWriter() {
		t.Fatal("jsonEventWriter should be stable per session")
	}
	if session.syscallHandlerRunner() != session.syscallHandlerRunner() {
		t.Fatal("syscallHandlerRunner should be stable per session")
	}
	if session.exitStatusCoordinator() != session.exitStatusCoordinator() {
		t.Fatal("exitStatusCoordinator should be stable per session")
	}
	if session.exitSyscallOutput() != session.exitSyscallOutput() {
		t.Fatal("exitSyscallOutput should be stable per session")
	}
	if session.syscallTextOutput() != session.syscallTextOutput() {
		t.Fatal("syscallTextOutput should be stable per session")
	}
	if session.lifecycleEventHandler() != session.lifecycleEventHandler() {
		t.Fatal("lifecycleEventHandler should be stable per session")
	}
	if session.syscallExitPipeline() != session.syscallExitPipeline() {
		t.Fatal("syscallExitPipeline should be stable per session")
	}
	if session.traceRecordDecoder() != session.traceRecordDecoder() {
		t.Fatal("traceRecordDecoder should be stable per session")
	}
	if session.traceEventReader() != session.traceEventReader() {
		t.Fatal("traceEventReader should be stable per session")
	}
	if session.traceEventRouter() != session.traceEventRouter() {
		t.Fatal("traceEventRouter should be stable per session")
	}
	if session.traceRunFinalizer() != session.traceRunFinalizer() {
		t.Fatal("traceRunFinalizer should be stable per session")
	}
	if session.commandExitHandler() != session.commandExitHandler() {
		t.Fatal("commandExitHandler should be stable per session")
	}
}

func TestTraceSessionPipelineUsesComposedDependencies(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{
		opts:      &cli.Options{},
		outWriter: &output,
	}

	pipeline := session.syscallExitPipeline()
	jsonWriter := session.jsonEventWriter()
	if session.syscallJSONOutput().writer != jsonWriter {
		t.Fatal("syscall JSON output should use composed JSON writer")
	}
	if session.exitSyscallOutput().jsonWriter != jsonWriter {
		t.Fatal("exit syscall output should use composed JSON writer")
	}

	if pipeline.json != session.syscallJSONOutput() {
		t.Fatal("pipeline should use composed JSON output")
	}
	if pipeline.exit != session.exitSyscallOutput() {
		t.Fatal("pipeline should use composed exit syscall output")
	}
	if pipeline.runner != session.syscallHandlerRunner() {
		t.Fatal("pipeline should use composed syscall handler runner")
	}
	if pipeline.text != session.syscallTextOutput() {
		t.Fatal("pipeline should use composed text output")
	}
	handlerEffects, ok := session.syscallHandlerRunner().effects.(*traceSessionSyscallHandlerEffects)
	if !ok {
		t.Fatalf("handler runner effects = %T, want *traceSessionSyscallHandlerEffects", session.syscallHandlerRunner().effects)
	}
	if handlerEffects.fdState != session.fdStateStore() {
		t.Fatal("handler runner should use session fd state store")
	}
	effects, ok := pipeline.effects.(*traceSessionSyscallExitEffects)
	if !ok {
		t.Fatalf("pipeline effects = %T, want *traceSessionSyscallExitEffects", pipeline.effects)
	}
	if effects.summary != session.summaryStats() {
		t.Fatal("pipeline should use session summary stats")
	}
	if effects.fdState != session.fdStateStore() {
		t.Fatal("pipeline should use session fd state store")
	}
	lifecycleEffects, ok := session.lifecycleEventHandler().effects.(*traceSessionLifecycleEffects)
	if !ok {
		t.Fatalf("lifecycle effects = %T, want *traceSessionLifecycleEffects", session.lifecycleEventHandler().effects)
	}
	if lifecycleEffects.fdState != session.fdStateStore() {
		t.Fatal("lifecycle handler should use session fd state store")
	}
	if lifecycleEffects.jsonWriter != jsonWriter {
		t.Fatal("lifecycle handler should use composed JSON writer")
	}
	router := session.traceEventRouter()
	if router.state != session.traceState() {
		t.Fatal("router should use session trace state")
	}
	if router.lifecycle != session.lifecycleEventHandler() {
		t.Fatal("router should use composed lifecycle handler")
	}
	if router.json != session.syscallJSONOutput() {
		t.Fatal("router should use composed JSON output")
	}
	if router.pipeline != session.syscallExitPipeline() {
		t.Fatal("router should use composed syscall exit pipeline")
	}
	if router.contextDeps.fdState != session.fdStateStore() {
		t.Fatal("router should use session fd state store for contexts")
	}
	if router.contextDeps.fdPath != session.fdStateStore() {
		t.Fatal("router should use session fd path reader for contexts")
	}
	if router.contextDeps.runtime != session.fdStateStore().Runtime() {
		t.Fatal("router should use session runtime service for contexts")
	}
	eventReader := session.traceEventReader()
	if eventReader.decoder != session.traceRecordDecoder() {
		t.Fatal("event reader should use composed record decoder")
	}
	if eventReader.sink != session.traceEventRouter() {
		t.Fatal("event reader should use composed event router")
	}
	finalizer := session.traceRunFinalizer()
	commandExit := session.commandExitHandler()
	if commandExit.exitStatus != session.exitStatusCoordinator() {
		t.Fatal("command exit handler should use composed exit status coordinator")
	}
	if commandExit.renderer != session.textRenderer() {
		t.Fatal("command exit handler should use composed text renderer")
	}
	if finalizer.exitStatus != session.exitStatusCoordinator() {
		t.Fatal("finalizer should use composed exit status coordinator")
	}
	if finalizer.summary != session.summaryStats() {
		t.Fatal("finalizer should use session summary stats")
	}
	if finalizer.bpfObjs != session.bpfObjs {
		t.Fatal("finalizer should use session BPF objects")
	}
}
