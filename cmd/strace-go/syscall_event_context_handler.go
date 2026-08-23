package main

import (
	"fmt"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func (ev syscallEventContext) eventView() syscallEventView {
	return ev.view
}

func (ev syscallEventContext) outputPayloadSections() []handler.PayloadSection {
	return ev.payloadSections
}

func (ev syscallEventContext) effectiveSyscallMeta() meta.Syscall {
	if ev.meta.Name != "" {
		return ev.meta
	}
	if ev.handlerContext != nil {
		if ev.handlerContext.ScMeta.Name != "" {
			return ev.handlerContext.ScMeta
		}
		if ev.handlerContext.SysName != "" {
			return meta.Syscall{Name: ev.handlerContext.SysName}
		}
	}
	return ev.meta
}

func (ev syscallEventContext) syscallName() string {
	if ev.meta.Name != "" {
		return ev.meta.Name
	}
	return ev.effectiveSyscallMeta().Name
}

func (ev syscallEventContext) handlerContextForFormatting() *handler.Context {
	return ev.handlerContext
}

func (ev syscallEventContext) decodedPayloadSections() []handler.PayloadSection {
	if ev.handlerContext == nil {
		return nil
	}
	return ev.handlerContext.PayloadSections
}

func (ev syscallEventContext) returnText(res handler.Result) string {
	view := ev.eventView()
	return formatSyscallRet(ev.syscallName(), view.ret, res, ev.handlerContextForFormatting())
}

func (ev syscallEventContext) handleWith(handle func(string, *handler.Context) handler.Result) handler.Result {
	if ev.handlerContext == nil {
		return handler.Result{}
	}
	if ev.handlerContext.HandlerDispatch != nil {
		return ev.handlerContext.HandlerDispatch.Handle(
			ev.handlerContext.SysId,
			ev.syscallName(),
			ev.handlerContext,
		)
	}
	if handle == nil {
		return handler.Result{}
	}
	return handle(ev.syscallName(), ev.handlerContext)
}

func syscallMeta(sysID uint32) meta.Syscall {
	if scMeta, ok := meta.SyscallTable[sysID]; ok {
		return scMeta
	}
	return meta.Syscall{Name: unknownSyscallName(sysID)}
}

func unknownSyscallName(sysID uint32) string {
	return fmt.Sprintf("sys_%d", sysID)
}

func (ev syscallEventContext) newHandlerContext(deps syscallEventContextDeps) *handler.Context {
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	context := deps.contextPool.acquire()
	if deps.contextPool == nil {
		applyHandlerContextSessionPorts(context, handlerContextSessionPortsFromDeps(deps))
	}
	context.Pid = int(view.pid)
	context.Tid = int(view.tid)
	context.TargetPid = ev.statePID
	context.SysId = view.sysID
	context.SysName = scMeta.Name
	context.Args = view.args
	context.Ret = view.ret
	context.ProbeRetEnter = view.probeRetEnter
	context.ProbeRetExit = view.probeRetExit
	context.PayloadSections = ev.outputPayloadSections()
	context.ScMeta = scMeta
	context.EventFDView = ev.handlerEventFDView()
	return context
}

func handlerContextSessionPortsFromDeps(deps syscallEventContextDeps) handlerContextSessionPorts {
	return handlerContextSessionPorts{
		meta:     deps.catalog,
		registry: deps.registry,
		dispatch: deps.handlerDispatch,
		decoder:  deps.decoder,
		opts:     deps.handlerOpts,
		fdState:  deps.fdStateReader(),
		runtime:  deps.runtimeService(),
	}
}

func (ev syscallEventContext) handlerEventFDView() handler.EventFDStateReader {
	if len(ev.eventFDView.paths) == 0 && len(ev.eventFDView.states) == 0 && ev.eventFDView.cwd == "" {
		return nil
	}
	return ev.eventFDView
}

func (ev syscallEventContext) releaseHandlerContext() {
	if ev.contextRecycler == nil {
		return
	}
	ev.contextRecycler.release(ev.handlerContext)
}
