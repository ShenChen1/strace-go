package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type handlerContextSessionPorts struct {
	meta     meta.CatalogPort
	registry handler.RegistryPort
	decoder  handler.SnapshotDecoder
	opts     handler.OptionsPort
	fdState  handler.FDStateReader
	runtime  handler.RuntimeServices
}

// handlerContextRecycler owns one reusable context for the single event consumer.
type handlerContextRecycler struct {
	cached          *handler.Context
	sessionPorts    handlerContextSessionPorts
	portsConfigured bool
}

func newHandlerContextRecycler() *handlerContextRecycler {
	return &handlerContextRecycler{}
}

func (r *handlerContextRecycler) configureSessionPorts(ports handlerContextSessionPorts) {
	if r == nil || r.portsConfigured {
		return
	}
	r.sessionPorts = ports
	r.portsConfigured = true
	if r.cached != nil {
		applyHandlerContextSessionPorts(r.cached, ports)
	}
}

func (r *handlerContextRecycler) acquire() *handler.Context {
	if r == nil || r.cached == nil {
		context := &handler.Context{}
		if r != nil && r.portsConfigured {
			applyHandlerContextSessionPorts(context, r.sessionPorts)
		}
		return context
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

func applyHandlerContextSessionPorts(
	context *handler.Context,
	ports handlerContextSessionPorts,
) {
	context.Meta = ports.meta
	context.Registry = ports.registry
	context.Decoder = ports.decoder
	context.Opts = ports.opts
	context.FDStateView = ports.fdState
	context.Runtime = ports.runtime
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
