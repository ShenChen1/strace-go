package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

type SyscallJSONOutput struct {
	opts    *cli.Options
	fdState event.FDPathReader
	writer  jsonEventWriter
}

type SyscallJSONOutputDeps struct {
	Opts    *cli.Options
	FDState event.FDPathReader
	Writer  jsonEventWriter
}

func newSyscallJSONOutput(deps SyscallJSONOutputDeps) *SyscallJSONOutput {
	return &SyscallJSONOutput{
		opts:    deps.Opts,
		fdState: deps.FDState,
		writer:  deps.Writer,
	}
}

func (s *traceSession) syscallJSONOutput() *SyscallJSONOutput {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.syscallJSON
}

func (o *SyscallJSONOutput) HandleEnter(ev syscallEventContext) {
	if !o.jsonMode() {
		return
	}
	if ev.shouldEmitRawEnter(o.fdState) {
		o.writeRawEvent(ev)
	}
}

func (o *SyscallJSONOutput) HandleDebugRaw(ev syscallEventContext) bool {
	if !o.jsonMode() || !o.opts.DebugEvents {
		return false
	}
	o.writeRawEvent(ev)
	return true
}

func (o *SyscallJSONOutput) HandleDecoded(ev syscallEventContext, res handler.Result) bool {
	if !o.jsonMode() {
		return false
	}
	status := successfulFailedOptions{
		successfulOnly: o.opts.SuccessfulOnly,
		failedOnly:     o.opts.FailedOnly,
		traceStatus:    o.opts.TraceStatus,
	}
	if ev.shouldEmitStatus(status) {
		o.writeDecodedEvent(ev, res)
	}
	return true
}

func (o *SyscallJSONOutput) jsonMode() bool {
	return o.opts != nil && o.opts.EventFormat == cli.EventFormatJSON
}

func (o *SyscallJSONOutput) writeRawEvent(ev syscallEventContext) {
	if o.writer != nil {
		o.writer.WriteRaw(ev)
	}
}

func (o *SyscallJSONOutput) writeDecodedEvent(ev syscallEventContext, res handler.Result) {
	if o.writer != nil {
		o.writer.WriteDecoded(ev, res)
	}
}
