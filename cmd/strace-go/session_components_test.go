package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceSessionCachesEventPipelineComponents(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{
		opts:      &cli.Options{},
		outWriter: &output,
	}

	if session.textRenderer() != session.textRenderer() {
		t.Fatal("textRenderer should be cached per session")
	}
	if session.syscallJSONOutput() != session.syscallJSONOutput() {
		t.Fatal("syscallJSONOutput should be cached per session")
	}
	if session.jsonEventWriter() != session.jsonEventWriter() {
		t.Fatal("jsonEventWriter should be cached per session")
	}
	if session.syscallHandlerRunner() != session.syscallHandlerRunner() {
		t.Fatal("syscallHandlerRunner should be cached per session")
	}
	if session.exitStatusCoordinator() != session.exitStatusCoordinator() {
		t.Fatal("exitStatusCoordinator should be cached per session")
	}
	if session.exitSyscallOutput() != session.exitSyscallOutput() {
		t.Fatal("exitSyscallOutput should be cached per session")
	}
	if session.syscallTextOutput() != session.syscallTextOutput() {
		t.Fatal("syscallTextOutput should be cached per session")
	}
	if session.lifecycleEventHandler() != session.lifecycleEventHandler() {
		t.Fatal("lifecycleEventHandler should be cached per session")
	}
	if session.syscallExitPipeline() != session.syscallExitPipeline() {
		t.Fatal("syscallExitPipeline should be cached per session")
	}
	if session.traceRecordDecoder() != session.traceRecordDecoder() {
		t.Fatal("traceRecordDecoder should be cached per session")
	}
	if session.traceEventReader() != session.traceEventReader() {
		t.Fatal("traceEventReader should be cached per session")
	}
	if session.traceEventRouter() != session.traceEventRouter() {
		t.Fatal("traceEventRouter should be cached per session")
	}
	if session.traceRunFinalizer() != session.traceRunFinalizer() {
		t.Fatal("traceRunFinalizer should be cached per session")
	}
	if session.commandExitHandler() != session.commandExitHandler() {
		t.Fatal("commandExitHandler should be cached per session")
	}
}

func TestTraceSessionPipelineUsesCachedDependencies(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{
		opts:      &cli.Options{},
		outWriter: &output,
	}

	pipeline := session.syscallExitPipeline()
	jsonWriter := session.jsonEventWriter()
	if session.syscallJSONOutput().writer != jsonWriter {
		t.Fatal("syscall JSON output should use cached JSON writer")
	}
	if session.exitSyscallOutput().jsonWriter != jsonWriter {
		t.Fatal("exit syscall output should use cached JSON writer")
	}

	if pipeline.json != session.syscallJSONOutput() {
		t.Fatal("pipeline should use cached JSON output")
	}
	if pipeline.exit != session.exitSyscallOutput() {
		t.Fatal("pipeline should use cached exit syscall output")
	}
	if pipeline.runner != session.syscallHandlerRunner() {
		t.Fatal("pipeline should use cached syscall handler runner")
	}
	if pipeline.text != session.syscallTextOutput() {
		t.Fatal("pipeline should use cached text output")
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
		t.Fatal("lifecycle handler should use cached JSON writer")
	}
	router := session.traceEventRouter()
	if router.state != session.traceState() {
		t.Fatal("router should use session trace state")
	}
	if router.lifecycle != session.lifecycleEventHandler() {
		t.Fatal("router should use cached lifecycle handler")
	}
	if router.json != session.syscallJSONOutput() {
		t.Fatal("router should use cached JSON output")
	}
	if router.pipeline != session.syscallExitPipeline() {
		t.Fatal("router should use cached syscall exit pipeline")
	}
	if router.contextDeps.fdState != session.fdStateStore() {
		t.Fatal("router should use session fd state store for contexts")
	}
	eventReader := session.traceEventReader()
	if eventReader.decoder != session.traceRecordDecoder() {
		t.Fatal("event reader should use cached record decoder")
	}
	if eventReader.sink != session.traceEventRouter() {
		t.Fatal("event reader should use cached event router")
	}
	finalizer := session.traceRunFinalizer()
	commandExit := session.commandExitHandler()
	if commandExit.exitStatus != session.exitStatusCoordinator() {
		t.Fatal("command exit handler should use cached exit status coordinator")
	}
	if commandExit.renderer != session.textRenderer() {
		t.Fatal("command exit handler should use cached text renderer")
	}
	if finalizer.exitStatus != session.exitStatusCoordinator() {
		t.Fatal("finalizer should use cached exit status coordinator")
	}
	if finalizer.summary != session.summaryStats() {
		t.Fatal("finalizer should use session summary stats")
	}
	if finalizer.bpfObjs != session.bpfObjs {
		t.Fatal("finalizer should use session BPF objects")
	}
}
