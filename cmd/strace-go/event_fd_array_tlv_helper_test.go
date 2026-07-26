package main

import "testing"

func setFDArrayExitTLVPayload(
	t *testing.T,
	eventRaw *bpfEvent,
	argIndex uint16,
	userPtr uint64,
	first uint32,
	second uint32,
) {
	t.Helper()
	data := fdArrayJSONData(first, second)
	setJSONTestTLVPayload(t, eventRaw, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     argIndex,
		userPtr: userPtr,
		userLen: uint32(len(data)),
		data:    data,
	})
}
