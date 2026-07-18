package main

import "strace-go/pkg/handler"

// rawEventEnvelope is the boundary object projected from the BPF carrier.
type rawEventEnvelope struct {
	valid           bool
	eventVersion    uint16
	pid             uint32
	tid             uint32
	sysID           uint32
	eventType       uint16
	eventFlags      uint32
	lifecycleAction uint32
	enterTime       uint64
	args            [6]uint64
	ret             int64
	duration        uint64
	ptr             uint64
	stackID         int32
	probeRetEnter   int32
	probeRetExit    int32
	snapshotText    string
	payload         []handler.PayloadSection
}

func (envelope rawEventEnvelope) lifecycleView() lifecycleEventView {
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
	}
}

func (envelope rawEventEnvelope) syscallView() syscallEventView {
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
		enterTime:     envelope.enterTime,
		ptr:           envelope.ptr,
		stackID:       envelope.stackID,
		probeRetEnter: envelope.probeRetEnter,
		probeRetExit:  envelope.probeRetExit,
	}
}

func (envelope rawEventEnvelope) isLifecycle() bool {
	return envelope.eventType == bpfEventTypeLifecycle
}

func (envelope rawEventEnvelope) isExit() bool {
	return envelope.eventType == bpfEventTypeExit
}
