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
	if session.traceEventRouter() != session.traceEventRouter() {
		t.Fatal("traceEventRouter should be cached per session")
	}
}

func TestTraceSessionPipelineUsesCachedDependencies(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{
		opts:      &cli.Options{},
		outWriter: &output,
	}

	pipeline := session.syscallExitPipeline()

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
}
