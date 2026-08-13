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
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatJSON}, traceSessionDeps{
		Events:    ringReader,
		TargetPID: 101,
		OutWriter: &output,
		State:     state,
		Clock:     clock,
	})

	if session.components == nil {
		t.Fatal("newTraceSession() left components nil")
	}
	components := session.components
	outputPolicy := session.dependencies.OutputPolicy
	if components.eventReader == nil || components.eventRouter == nil || components.recordDecoder == nil {
		t.Fatalf("event graph = %+v, want reader/router/decoder", components)
	}
	if components.handlerRegistry == nil || components.handlerRunner == nil {
		t.Fatal("event graph is missing the session handler registry")
	}
	if components.eventRouter.contextDeps.registry != components.handlerRegistry {
		t.Fatal("event router does not use the session handler registry")
	}
	if deps := newSyscallEventContextDeps(session); deps.registry != components.handlerRegistry {
		t.Fatal("session event context helper does not reuse the composed handler registry")
	}
	contextDeps := newSyscallEventContextDeps(session)
	if contextDeps.decoder != session.dependencies.Decoder || contextDeps.catalog != session.dependencies.Catalog {
		t.Fatal("event context does not use dependencies-owned decoder/catalog")
	}
	if contextDeps.fdState != session.dependencies.FDState || contextDeps.runtime != session.dependencies.Runtime {
		t.Fatal("event context does not use dependencies-owned runtime state")
	}
	if components.exitSyscall.handleSyscall == nil {
		t.Fatal("exit syscall output is missing the session handler resolver")
	}
	if outputPolicy == nil || components.textRenderer.policy != outputPolicy {
		t.Fatal("text renderer does not use the session output policy snapshot")
	}
	if session.dependencies.EventPolicy == nil ||
		contextDeps.handlerOpts != session.dependencies.EventPolicy.HandlerOptions() ||
		contextDeps.filter != session.dependencies.EventPolicy.FilterOptions() {
		t.Fatal("event context does not use the dependency-owned event policy snapshot")
	}
	execOutput, ok := components.syscallText.exec.(*ExecSyscallOutput)
	if !ok || execOutput.policy != outputPolicy {
		t.Fatal("syscall text output does not use the session exec policy snapshot")
	}
	if components.syscallText.format != outputPolicy || components.syscallText.policy != outputPolicy ||
		components.syscallJSON.format != outputPolicy ||
		components.syscallJSON.policy != outputPolicy || components.exitSyscall.policy != outputPolicy ||
		components.lifecycleHandler.policy != outputPolicy ||
		components.runFinalizer.formatPolicy != outputPolicy || components.commandExitHandler.policy != outputPolicy {
		t.Fatal("session output components do not share one policy snapshot")
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
	if components.eventReader.clock != clock || session.dependencies.Clock != clock {
		t.Fatal("session and event reader do not share the injected clock")
	}
	if components.textRenderer.timeFormatter == nil || components.textRenderer.timeFormatter.NowMonoNs() != clock.NowMonoNs() {
		t.Fatal("text renderer does not use the injected session time source")
	}
	runState := newTraceRunState(traceRunStateDeps{
		clock:    session.dependencies.Clock,
		pidProbe: session.dependencies.PIDProbe,
	})
	if runState.clock != clock || runState.pidProbe != session.dependencies.PIDProbe {
		t.Fatal("run state does not use the session-owned ports")
	}
	if components.eventRouter.state != state {
		t.Fatal("event router did not receive the session state")
	}
	if session.traceEventReader() != components.eventReader || session.traceEventRouter() != components.eventRouter {
		t.Fatal("component accessors replaced eagerly composed instances")
	}
	if got := session.traceState(); got != state {
		t.Fatalf("session state = %+v, want injected deferred state", got)
	}
	if !state.deferUnmatchedExits {
		t.Fatalf("injected session state = %+v, want deferred state", state)
	}
}

func TestTraceSessionEagerGraphUsesOneExitStatusCoordinator(t *testing.T) {
	session := newTestTraceSession(traceSessionDeps{})
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
	session := newTestTraceSession(traceSessionDeps{
		OutWriter: &output,
	})

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

func TestZeroValueTraceSessionDoesNotBuildComponentGraph(t *testing.T) {
	session := &traceSession{}
	if session.traceEventRouter() != nil {
		t.Fatal("zero-value traceSession must not construct an event graph")
	}
	if session.components != nil {
		t.Fatal("zero-value traceSession unexpectedly gained components")
	}
}

func TestTraceSessionPipelineUsesComposedDependencies(t *testing.T) {
	var output bytes.Buffer
	session := newTestTraceSession(traceSessionDeps{
		OutWriter: &output,
	})

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
	if effects.offsets != session.fdStateStore() {
		t.Fatal("pipeline should use session fd offset port")
	}
	if effects.close != session.fdStateStore() {
		t.Fatal("pipeline should use session fd close port")
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
	if router.contextDeps.runtime != session.runtimeService() {
		t.Fatal("router should use session runtime service for contexts")
	}
	if router.contextDeps.runtime == nil {
		t.Fatal("router should receive a non-nil session runtime service")
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
	if finalizer.statsReader != session.dependencies.Stats {
		t.Fatal("finalizer should use the injected stats reader")
	}
}

func TestTraceSessionOwnsRuntimeSeparatelyFromFDState(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:3": "/dev/null"}, nil)
	runtime := handler.NewRuntime()
	session := newTestTraceSession(traceSessionDeps{
		FDState: store,
		Runtime: runtime,
	})

	deps := session.traceEventRouter().contextDeps
	if deps.runtime != runtime {
		t.Fatal("session composition replaced the injected runtime service")
	}
	if deps.fdState != store {
		t.Fatal("session composition replaced the injected FD state store")
	}
	if got, ok := store.Path(101, 3); !ok || got != "/dev/null" {
		t.Fatalf("FD state path = %q, %v; want /dev/null, true", got, ok)
	}
	if got := runtime.NextFiemapCall(101); got != 1 {
		t.Fatalf("injected runtime first call = %d, want 1", got)
	}
	if got := session.runtimeService().NextFiemapCall(101); got != 2 {
		t.Fatalf("session runtime second call = %d, want 2", got)
	}
	if got, ok := store.Path(101, 3); !ok || got != "/dev/null" {
		t.Fatalf("FD state path after runtime calls = %q, %v; want /dev/null, true", got, ok)
	}
}
