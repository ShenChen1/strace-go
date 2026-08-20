package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

// handlerContextRecycler owns one reusable context for the single event consumer.
type handlerContextRecycler struct {
	cached *handler.Context
}

func newHandlerContextRecycler() *handlerContextRecycler {
	return &handlerContextRecycler{}
}

func (r *handlerContextRecycler) acquire() *handler.Context {
	if r == nil || r.cached == nil {
		return &handler.Context{}
	}
	context := r.cached
	r.cached = nil
	return context
}

func (r *handlerContextRecycler) release(context *handler.Context) {
	if r == nil || context == nil {
		return
	}
	resetHandlerContextEventState(context)
	r.cached = context
}

// resetHandlerContextEventState drops per-event data while retaining session-owned ports.
func resetHandlerContextEventState(context *handler.Context) {
	context.Pid = 0
	context.Tid = 0
	context.TargetPid = 0
	context.SysId = 0
	context.SysName = ""
	context.Args = [6]uint64{}
	context.Ret = 0
	context.ProbeRetEnter = 0
	context.ProbeRetExit = 0
	context.PayloadSections = nil
	context.ScMeta = meta.Syscall{}
	context.EventFDView = nil
}
