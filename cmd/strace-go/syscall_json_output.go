package main

import (
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

type SyscallJSONOutput struct {
	enabled bool
	policy  traceEventOutputPolicy
	fdState event.FDPathReader
	writer  jsonEventWriter
}

type SyscallJSONOutputDeps struct {
	Format  traceFormatPolicy
	Policy  traceEventOutputPolicy
	FDState event.FDPathReader
	Writer  jsonEventWriter
}

func newSyscallJSONOutput(deps SyscallJSONOutputDeps) *SyscallJSONOutput {
	return &SyscallJSONOutput{
		enabled: deps.Format != nil && deps.Format.IsJSON(),
		policy:  deps.Policy,
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
	if !o.jsonMode() || o.policy == nil || !o.policy.DebugEvents() {
		return false
	}
	o.writeRawEvent(ev)
	return true
}

func (o *SyscallJSONOutput) HandleDecoded(ev syscallEventContext, res handler.Result) bool {
	if !o.jsonMode() {
		return false
	}
	if o.policy != nil && o.policy.ShouldEmit(ev, false) {
		o.writeDecodedEvent(ev, res)
	}
	return true
}

func (o *SyscallJSONOutput) jsonMode() bool {
	return o != nil && o.enabled
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
