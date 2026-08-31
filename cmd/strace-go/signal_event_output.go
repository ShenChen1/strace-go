package main

import (
	"fmt"

	"strace-go/pkg/meta"
)

const (
	signalCodeUser       int32 = 0
	signalCodeKernel     int32 = 128
	signalCodeQueue      int32 = -1
	signalCodeTimer      int32 = -2
	signalCodeMesgQ      int32 = -3
	signalCodeAsync      int32 = -4
	signalCodeSigIO      int32 = -5
	signalCodeTKill      int32 = -6
	signalCodeSegvMapErr int32 = 1
	signalCodeSegvAccErr int32 = 2
)

type signalEventView struct {
	pid       uint32
	tid       uint32
	enterTime uint64
	signo     uint32
	error     int32
	code      int32
	senderPID uint32
	senderUID uint32
	stackID   int32
	address   uint64
}

type signalEventSink interface {
	HandleSignal(signalEventView)
}

type signalEventRenderer interface {
	PrintSignalEvent(signalEventView, string)
}

type SignalEventOutput struct {
	policy   traceSignalOutputPolicy
	renderer signalEventRenderer
	catalog  meta.CatalogPort
}

func newSignalEventOutput(
	policy traceSignalOutputPolicy,
	renderer signalEventRenderer,
	catalog meta.CatalogPort,
) *SignalEventOutput {
	return &SignalEventOutput{policy: policy, renderer: renderer, catalog: catalog}
}

func (o *SignalEventOutput) HandleSignal(view signalEventView) {
	if o == nil || o.renderer == nil {
		return
	}
	if o.policy != nil && !o.policy.ShouldEmitSignal(view.signo) {
		return
	}
	signalName := fmt.Sprintf("%d", view.signo)
	if o.catalog != nil {
		signalName = o.catalog.DecodeFlags(uint64(view.signo), "signalnames")
	}
	o.renderer.PrintSignalEvent(view, signalName)
}

func signalCodeName(signalName string, code int32) string {
	if signalName == "SIGSEGV" {
		switch code {
		case signalCodeSegvMapErr:
			return "SEGV_MAPERR"
		case signalCodeSegvAccErr:
			return "SEGV_ACCERR"
		}
	}
	if signalName == "SIGCHLD" {
		return childSignalCodeName(code)
	}
	switch code {
	case signalCodeUser:
		return "SI_USER"
	case signalCodeKernel:
		return "SI_KERNEL"
	case signalCodeQueue:
		return "SI_QUEUE"
	case signalCodeTimer:
		return "SI_TIMER"
	case signalCodeMesgQ:
		return "SI_MESGQ"
	case signalCodeAsync:
		return "SI_ASYNCIO"
	case signalCodeSigIO:
		return "SI_SIGIO"
	case signalCodeTKill:
		return "SI_TKILL"
	default:
		return ""
	}
}

func childSignalCodeName(code int32) string {
	switch code {
	case 1:
		return "CLD_EXITED"
	case 2:
		return "CLD_KILLED"
	case 3:
		return "CLD_DUMPED"
	case 4:
		return "CLD_TRAPPED"
	case 5:
		return "CLD_STOPPED"
	case 6:
		return "CLD_CONTINUED"
	default:
		return ""
	}
}

func signalCodeHasSender(signalName string, code int32) bool {
	return signalName == "SIGCHLD" || code == signalCodeUser || code == signalCodeQueue || code == signalCodeTKill
}

var _ signalEventSink = (*SignalEventOutput)(nil)
