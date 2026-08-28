package main

import (
	"fmt"

	"strace-go/pkg/meta"
)

const (
	signalCodeUser   int32 = 0
	signalCodeKernel int32 = 128
	signalCodeQueue  int32 = -1
	signalCodeTimer  int32 = -2
	signalCodeMesgQ  int32 = -3
	signalCodeAsync  int32 = -4
	signalCodeSigIO  int32 = -5
	signalCodeTKill  int32 = -6
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

func signalCodeName(code int32) string {
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

func signalCodeHasSender(code int32) bool {
	return code == signalCodeUser || code == signalCodeQueue || code == signalCodeTKill
}

var _ signalEventSink = (*SignalEventOutput)(nil)
