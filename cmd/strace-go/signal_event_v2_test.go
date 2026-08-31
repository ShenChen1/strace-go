package main

import (
	"encoding/binary"
	"testing"
)

func TestDecodeTraceEventV2SignalEnvelope(t *testing.T) {
	raw := traceEventV2SignalSample(traceEventV2SampleSpec{
		pid:        101,
		tid:        102,
		tsNs:       900,
		signal:     2,
		signalErr:  0,
		signalCode: 0,
		senderPID:  201,
		senderUID:  1000,
	})
	body := raw[traceEventV2HeaderLen:]
	binary.LittleEndian.PutUint64(body[traceEventV2SignalAddressOffset:], 0x1234)

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a valid signal sample")
	}
	if !envelope.valid || envelope.eventType != bpfEventTypeSignal || envelope.enterTime != 900 {
		t.Fatalf("signal envelope = %+v, want valid signal at 900", envelope)
	}
	if envelope.signal != 2 || envelope.signalErr != 0 || envelope.signalCode != 0 ||
		envelope.senderPID != 201 || envelope.senderUID != 1000 || envelope.signalAddress != 0x1234 {
		t.Fatalf("signal identity = %+v", envelope)
	}
}

func TestDecodeTraceEventV2RejectsShortSignalBody(t *testing.T) {
	raw := traceEventV2SignalSample(traceEventV2SampleSpec{signal: 2})
	if _, ok := decodeTraceEventV2Envelope(raw[:len(raw)-1]); ok {
		t.Fatal("decodeTraceEventV2Envelope accepted a truncated signal body")
	}
}

func traceEventV2SignalSample(spec traceEventV2SampleSpec) []byte {
	size := traceEventV2HeaderLen + traceEventV2SignalBodyLen
	spec.eventType = bpfEventTypeSignal
	raw := traceEventV2HeaderSample(spec, size)
	body := raw[traceEventV2HeaderLen:]
	binary.LittleEndian.PutUint32(body[traceEventV2SignalNumberOffset:], spec.signal)
	binary.LittleEndian.PutUint32(body[traceEventV2SignalErrnoOffset:], uint32(spec.signalErr))
	binary.LittleEndian.PutUint32(body[traceEventV2SignalCodeOffset:], uint32(spec.signalCode))
	binary.LittleEndian.PutUint32(body[traceEventV2SignalSenderPIDOffset:], spec.senderPID)
	binary.LittleEndian.PutUint32(body[traceEventV2SignalSenderUIDOffset:], spec.senderUID)
	return raw
}
