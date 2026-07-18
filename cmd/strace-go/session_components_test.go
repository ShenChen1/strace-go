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
}
