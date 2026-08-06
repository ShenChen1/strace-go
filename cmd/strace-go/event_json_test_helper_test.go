package main

import (
	"testing"

	"strace-go/pkg/meta"
)

func newJSONSyscallEventFromTLVForTest(
	t *testing.T,
	syscallName string,
	eventType uint16,
	args [6]uint64,
	ret int64,
	payload []byte,
) jsonSyscallEvent {
	t.Helper()
	envelope := testTLVSyscallEnvelope(t, syscallName, eventType, args, ret, payload)
	return newJSONSyscallEventFromView(envelope.syscallView(), meta.Syscall{Name: syscallName}, envelope.payload)
}

func payloadTLVBytesForTest(t *testing.T, sections ...payloadTLVTestSection) []byte {
	t.Helper()
	var payload []byte
	for _, section := range sections {
		payload = append(payload, payloadTLVBytes(t, section)...)
	}
	return payload
}
