package main

import (
	"testing"

	"strace-go/pkg/handler"
)

type fakePipelineJSONPort struct{}

func (*fakePipelineJSONPort) HandleDebugRaw(syscallEventContext) bool {
	return false
}

func (*fakePipelineJSONPort) HandleDecoded(syscallEventContext, handler.Result) bool {
	return false
}

type fakePipelineExitPort struct{}

func (*fakePipelineExitPort) Handle(syscallEventContext) bool {
	return false
}

type fakePipelineRunnerPort struct{}

func (*fakePipelineRunnerPort) Handle(syscallEventContext) (handler.Result, bool) {
	return handler.Result{}, false
}

func (*fakePipelineRunnerPort) Decode(syscallEventContext) handler.Result {
	return handler.Result{ReturnDesc: "decoded"}
}

type fakePipelineTextPort struct{}

func (*fakePipelineTextPort) HandleEvent(syscallEventContext, handler.Result) {}

func (*fakePipelineTextPort) HandleUnfinished(syscallEventContext, handler.Result) bool {
	return true
}

func (*fakePipelineTextPort) canHandleUnfinished(syscallEventContext) bool {
	return true
}

func TestSyscallExitPipelineAcceptsNarrowOutputPorts(t *testing.T) {
	json := &fakePipelineJSONPort{}
	exit := &fakePipelineExitPort{}
	runner := &fakePipelineRunnerPort{}
	text := &fakePipelineTextPort{}
	pipeline := newSyscallExitPipeline(SyscallExitPipelineDeps{
		JSON:   json,
		Exit:   exit,
		Runner: runner,
		Text:   text,
	})

	if pipeline.json != json || pipeline.exit != exit || pipeline.runner != runner || pipeline.text != text {
		t.Fatal("pipeline did not retain injected output ports")
	}
	if !pipeline.HandleUnfinished(syscallEventContext{}) {
		t.Fatal("pipeline did not dispatch unfinished event through narrow ports")
	}
}

var (
	_ syscallJSONOutputPort    = (*fakePipelineJSONPort)(nil)
	_ exitSyscallOutputPort    = (*fakePipelineExitPort)(nil)
	_ syscallHandlerRunnerPort = (*fakePipelineRunnerPort)(nil)
	_ syscallTextOutputPort    = (*fakePipelineTextPort)(nil)
)
