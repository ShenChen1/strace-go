package main

import "strace-go/pkg/handler"

type SyscallHandlerRunner struct {
	handleSyscall func(string, *handler.Context) handler.Result
	updateFDState func(syscallEventContext)
}

type SyscallHandlerRunnerDeps struct {
	HandleSyscall func(string, *handler.Context) handler.Result
	UpdateFDState func(syscallEventContext)
}

func newSyscallHandlerRunner(deps SyscallHandlerRunnerDeps) *SyscallHandlerRunner {
	return &SyscallHandlerRunner{
		handleSyscall: deps.HandleSyscall,
		updateFDState: deps.UpdateFDState,
	}
}

func (s *traceSession) syscallHandlerRunner() *SyscallHandlerRunner {
	if s.syscallRunnerCache == nil {
		s.syscallRunnerCache = newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
			HandleSyscall: defaultHandleSyscall,
			UpdateFDState: s.updateFDState,
		})
	}
	return s.syscallRunnerCache
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

func (r *SyscallHandlerRunner) update(ev syscallEventContext) {
	if r.updateFDState != nil {
		r.updateFDState(ev)
	}
}

func defaultHandleSyscall(name string, ctx *handler.Context) handler.Result {
	return handler.Get(name).Handle(ctx)
}
