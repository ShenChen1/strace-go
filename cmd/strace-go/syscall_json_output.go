package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type SyscallJSONOutput struct {
	opts         *cli.Options
	pathMap      map[string]string
	writeRaw     func(*bpfEvent, meta.Syscall)
	writeDecoded func(syscallEventContext, handler.Result)
}

type SyscallJSONOutputDeps struct {
	Opts         *cli.Options
	PathMap      map[string]string
	WriteRaw     func(*bpfEvent, meta.Syscall)
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

func (o *SyscallJSONOutput) HandleEnter(eventRaw *bpfEvent, view syscallEventView, scMeta meta.Syscall, statePID int) {
	if !o.jsonMode() {
		return
	}
	if o.opts.DebugEvents || checkShouldPrintFromView(view, scMeta, "", false, statePID, o.opts, o.pathMap) {
		o.writeRawEvent(eventRaw, scMeta)
	}
}

func (o *SyscallJSONOutput) HandleDebugRaw(eventRaw *bpfEvent, scMeta meta.Syscall) bool {
	if !o.jsonMode() || !o.opts.DebugEvents {
		return false
	}
	o.writeRawEvent(eventRaw, scMeta)
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

func (o *SyscallJSONOutput) writeRawEvent(eventRaw *bpfEvent, scMeta meta.Syscall) {
	if o.writeRaw != nil {
		o.writeRaw(eventRaw, scMeta)
	}
}

func (o *SyscallJSONOutput) writeDecodedEvent(ev syscallEventContext, res handler.Result) {
	if o.writeDecoded != nil {
		o.writeDecoded(ev, res)
	}
}
