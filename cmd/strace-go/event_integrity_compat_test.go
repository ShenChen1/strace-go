package main

import (
	"encoding/binary"
	"testing"
)

func TestIntegrityLegacyV2HeaderRemainsDecodable(t *testing.T) {
	raw := traceEventV2ExitSample(t, traceEventV2SampleSpec{pid: 12, tid: 12, ret: 7})
	const legacyHeaderLen = 56
	legacy := append(append([]byte(nil), raw[:legacyHeaderLen]...), raw[traceEventV2HeaderLen:]...)
	binary.LittleEndian.PutUint16(legacy[traceEventV2HeaderVersionOffset:], 2)
	binary.LittleEndian.PutUint16(legacy[traceEventV2HeaderLenOffset:], legacyHeaderLen)
	binary.LittleEndian.PutUint32(legacy[traceEventV2HeaderSizeOffset:], uint32(len(legacy)))
	ev, ok := decodeTraceEventV2Envelope(legacy)
	if !ok || ev.ret != 7 || ev.pid != 12 {
		t.Fatalf("legacy event-v2 rejected: ok=%v event=%+v", ok, ev)
	}
}

func TestIntegrityFirstCPURecordEstablishesBaseline(t *testing.T) {
	i := newTraceIntegrity(traceIntegrityDeps{})
	for _, ev := range []traceEventEnvelope{{cpu: 3, seq: 100}, {cpu: 3, seq: 101}, {cpu: 9, seq: 900}} {
		i.Observe(&ev)
	}
	if i.Snapshot().Tainted {
		t.Fatalf("attach baseline reported as loss: %+v", i.Snapshot())
	}
}

func TestIntegrityLegacyRecordCannotHideExistingTaint(t *testing.T) {
	i := newTraceIntegrity(traceIntegrityDeps{})
	i.InvalidRecord()
	ev := traceEventEnvelope{legacyIntegrity: true, tid: 12, pid: 12}
	i.Observe(&ev)
	if !ev.tainted || !ev.correlationTainted || ev.integrityEpoch == 0 {
		t.Fatalf("legacy record hid known degradation: %+v", ev.recordIntegrity())
	}
}
