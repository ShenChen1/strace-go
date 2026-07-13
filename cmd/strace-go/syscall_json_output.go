package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

type SyscallJSONOutput struct {
	opts         *cli.Options
	pathMap      map[string]string
	writeRaw     func(syscallEventContext)
	writeDecoded func(syscallEventContext, handler.Result)
}

type SyscallJSONOutputDeps struct {
	Opts         *cli.Options
	PathMap      map[string]string
	WriteRaw     func(syscallEventContext)
	WriteDecoded func(syscallEventContext, handler.Result)
}

func newSyscallJSONOutput(deps SyscallJSONOutputDeps) *SyscallJSONOutput {
	return &SyscallJSONOutput{
		opts:         deps.Opts,
		pathMap:      deps.PathMap,
		writeRaw:     deps.WriteRaw,
		writeDecoded: deps.WriteDecoded,
	}
}

func (s *traceSession) syscallJSONOutput() *SyscallJSONOutput {
	if s.syscallJSONCache == nil {
		s.syscallJSONCache = newSyscallJSONOutput(SyscallJSONOutputDeps{
			Opts:         s.opts,
			PathMap:      s.fdStateStore().PathMap(),
			WriteRaw:     s.writeJSONRawEvent,
			WriteDecoded: s.writeJSONDecodedEvent,
		})
	}
	return s.syscallJSONCache
}

func (o *SyscallJSONOutput) HandleEnter(ev syscallEventContext) {
	if !o.jsonMode() {
		return
	}
	if ev.shouldEmitRawEnter(o.opts, o.pathMap) {
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
	if o.writeRaw != nil {
		o.writeRaw(ev)
	}
}

func (o *SyscallJSONOutput) writeDecodedEvent(ev syscallEventContext, res handler.Result) {
	if o.writeDecoded != nil {
		o.writeDecoded(ev, res)
	}
}
