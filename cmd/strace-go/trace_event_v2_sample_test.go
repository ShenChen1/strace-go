package main

type traceEventV2SampleSpec struct {
	eventType        uint16
	pid              uint32
	tid              uint32
	sysID            uint32
	flags            uint32
	tsNs             uint64
	action           uint32
	duration         uint64
	cpuDuration      uint64
	ret              int64
	probeRetEnter    int32
	probeRetExit     int32
	stackID          int32
	kvmExitReason    uint32
	args             [6]uint64
	payload          []byte
	signal           uint32
	signalErr        int32
	signalCode       int32
	senderPID        uint32
	senderUID        uint32
	signalStatus     int32
	signalUserTime   int64
	signalSystemTime int64
	comm             string
}
