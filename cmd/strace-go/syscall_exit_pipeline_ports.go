package main

import "strace-go/pkg/handler"

type syscallJSONOutputPort interface {
	HandleDebugRaw(syscallEventContext) bool
	HandleDecoded(syscallEventContext, handler.Result) bool
}

type exitSyscallOutputPort interface {
	Handle(syscallEventContext) bool
}

type syscallHandlerRunnerPort interface {
	Handle(syscallEventContext) (handler.Result, bool)
	Decode(syscallEventContext) handler.Result
}

type syscallTextOutputPort interface {
	HandleEvent(syscallEventContext, handler.Result)
	HandleUnfinished(syscallEventContext, handler.Result) bool
	canHandleUnfinished(syscallEventContext) bool
}

var (
	_ syscallJSONOutputPort    = (*SyscallJSONOutput)(nil)
	_ exitSyscallOutputPort    = (*ExitSyscallOutput)(nil)
	_ syscallHandlerRunnerPort = (*SyscallHandlerRunner)(nil)
	_ syscallTextOutputPort    = (*SyscallTextOutput)(nil)
)
