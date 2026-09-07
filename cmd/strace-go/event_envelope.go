package main

import "strace-go/pkg/handler"

// traceEventEnvelope is the boundary object projected from the BPF carrier.
type traceEventEnvelope struct {
	valid            bool
	eventVersion     uint16
	pid              uint32
	tid              uint32
	sysID            uint32
	eventType        uint16
	eventFlags       uint32
	lifecycleAction  uint32
	enterTime        uint64
	args             [6]uint64
	ret              int64
	duration         uint64
	cpuDuration      uint64
	stackID          int32
	kvmExitReason    uint32
	probeRetEnter    int32
	probeRetExit     int32
	snapshotText     string
	signal           uint32
	signalErr        int32
	signalCode       int32
	senderPID        uint32
	senderUID        uint32
	signalAddress    uint64
	signalStatus     int32
	signalUserTime   int64
	signalSystemTime int64
	comm             string
	payload          []handler.PayloadSection
}

func (envelope traceEventEnvelope) lifecycleView() lifecycleEventView {
	return lifecycleEventView{
		valid:        envelope.valid,
		eventVersion: envelope.eventVersion,
		eventType:    envelope.eventType,
		eventFlags:   envelope.eventFlags,
		action:       envelope.lifecycleAction,
		pid:          envelope.pid,
		tid:          envelope.tid,
		args:         envelope.args,
		enterTime:    envelope.enterTime,
		snapshotText: envelope.snapshotText,
		comm:         envelope.comm,
	}
}

func (envelope traceEventEnvelope) syscallView() syscallEventView {
	return syscallEventView{
		valid:         envelope.valid,
		eventVersion:  envelope.eventVersion,
		pid:           envelope.pid,
		tid:           envelope.tid,
		sysID:         envelope.sysID,
		eventType:     envelope.eventType,
		eventFlags:    envelope.eventFlags,
		args:          envelope.args,
		ret:           envelope.ret,
		duration:      envelope.duration,
		cpuDuration:   envelope.cpuDuration,
		enterTime:     envelope.enterTime,
		stackID:       envelope.stackID,
		kvmExitReason: envelope.kvmExitReason,
		probeRetEnter: envelope.probeRetEnter,
		probeRetExit:  envelope.probeRetExit,
		comm:          envelope.comm,
	}
}

func (envelope traceEventEnvelope) signalView() signalEventView {
	return signalEventView{
		pid:        envelope.pid,
		tid:        envelope.tid,
		enterTime:  envelope.enterTime,
		signo:      envelope.signal,
		error:      envelope.signalErr,
		code:       envelope.signalCode,
		senderPID:  envelope.senderPID,
		senderUID:  envelope.senderUID,
		stackID:    envelope.stackID,
		address:    envelope.signalAddress,
		status:     envelope.signalStatus,
		userTime:   envelope.signalUserTime,
		systemTime: envelope.signalSystemTime,
	}
}

func (envelope traceEventEnvelope) isLifecycle() bool {
	return envelope.eventType == bpfEventTypeLifecycle
}

func (envelope traceEventEnvelope) isSignal() bool {
	return envelope.eventType == bpfEventTypeSignal
}

func (envelope traceEventEnvelope) isExit() bool {
	return envelope.eventType == bpfEventTypeExit
}
