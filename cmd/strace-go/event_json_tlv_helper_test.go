package main

import "testing"

func setJSONTestTLVPayload(t *testing.T, eventRaw *bpfEvent, sections ...payloadTLVTestSection) {
	t.Helper()
	var payload []byte
	for _, section := range sections {
		payload = append(payload, payloadTLVBytes(t, section)...)
	}
	setTestTLVPayloadBytes(t, eventRaw, payload)
}

func setTestTLVPayloadBytes(t *testing.T, eventRaw *bpfEvent, payload []byte) {
	t.Helper()
	eventRaw.EventFlags |= bpfEventFlagPayloadTLV
	eventRaw.DataLen = uint32(len(payload))
	copy(eventRaw.StrArg[:], payload)
}
