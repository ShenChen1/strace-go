package main

import "strace-go/pkg/handler"

type SyscallHandlerRunner struct {
	handleSyscall func(string, *handler.Context) handler.Result
	effects       SyscallHandlerEffects
}

type SyscallHandlerRunnerDeps struct {
	HandleSyscall func(string, *handler.Context) handler.Result
	Effects       SyscallHandlerEffects
}

type SyscallHandlerEffects interface {
	UpdateFDState(syscallEventContext)
}

type traceSessionSyscallHandlerEffects struct {
	fdState *FDStateStore
}

func newTraceSessionSyscallHandlerEffects(fdState *FDStateStore) *traceSessionSyscallHandlerEffects {
	return &traceSessionSyscallHandlerEffects{fdState: fdState}
}

func (e *traceSessionSyscallHandlerEffects) UpdateFDState(ev syscallEventContext) {
	ev.updateFDState(e.fdState)
}

func newSyscallHandlerRunner(deps SyscallHandlerRunnerDeps) *SyscallHandlerRunner {
	return &SyscallHandlerRunner{
		handleSyscall: deps.HandleSyscall,
		effects:       deps.Effects,
	}
}

func (s *traceSession) syscallHandlerRunner() *SyscallHandlerRunner {
	components := s.componentsOrBuild()
	if components == nil {
		return nil
	}
	return components.handlerRunner
}

// IMPACT: Handle owns handler decoding and FD state side effects for syscall exit events.
func (r *SyscallHandlerRunner) Handle(ev syscallEventContext) (handler.Result, bool) {
	if !ev.shouldRunHandler() {
		r.update(ev)
		return handler.Result{}, false
	}
	res := ev.handleWith(r.handleSyscall)
	r.update(ev)
	return res, ev.shouldOutput()
}

func (r *SyscallHandlerRunner) Decode(ev syscallEventContext) handler.Result {
	if r == nil || r.handleSyscall == nil || !ev.shouldRunHandler() {
		return handler.Result{}
	}
	return ev.handleWith(r.handleSyscall)
}

func (r *SyscallHandlerRunner) update(ev syscallEventContext) {
	if r.effects != nil {
		r.effects.UpdateFDState(ev)
	}
}

func defaultHandleSyscall(name string, ctx *handler.Context) handler.Result {
	return handler.Get(name).Handle(ctx)
}
