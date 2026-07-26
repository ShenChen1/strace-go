package main

import "testing"

func testTLVSyscallEnvelope(
	t *testing.T,
	syscallName string,
	eventType uint16,
	args [6]uint64,
	ret int64,
	payload []byte,
) traceEventEnvelope {
	t.Helper()
	spec := traceEventV2SampleSpec{
		pid:     101,
		tid:     101,
		sysID:   syscallIDByName(t, syscallName),
		flags:   bpfEventFlagPayloadTLV,
		args:    args,
		ret:     ret,
		payload: payload,
	}
	var raw []byte
	switch eventType {
	case bpfEventTypeEnter:
		raw = traceEventV2EnterSample(t, spec)
	case bpfEventTypeExit:
		raw = traceEventV2ExitSample(t, spec)
	default:
		t.Fatalf("unsupported TLV syscall event type %d", eventType)
	}
	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatalf("decodeTraceEventV2Envelope rejected %s event type %d", syscallName, eventType)
	}
	return envelope
}
