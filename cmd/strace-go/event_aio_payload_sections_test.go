package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
)

const (
	aioPayloadPointerSize    = 8
	aioPayloadIocbSize       = 64
	aioPayloadEventsElemSize = 32
)

func TestJSONSyscallEventIncludesAioSetupPayloadSection(t *testing.T) {
	args := [6]uint64{128, 0x1000}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     1,
			userPtr: 0x1000,
			userLen: aioPayloadPointerSize,
			data:    aioTestPointerBytes(0xabc),
		},
	)

	sections := aioJSONPayloadSections(t, "io_setup", bpfEventTypeExit, args, 0, payload)
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	assertAioJSONSection(t, sections[0], "struct", "out", 1, 0x1000, aioTestPointerBytes(0xabc))
}

func TestJSONSyscallEventIncludesAioSubmitPayloadSections(t *testing.T) {
	iocb0 := aioTestIocbData(1, 0x4000, 3)
	iocb1 := aioTestIocbData(0, 0x5000, 4)
	args := [6]uint64{0xabc, 2, 0x1000}
	pointers := append(aioTestPointerBytes(0x2000), aioTestPointerBytes(0x3000)...)
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     2,
			userPtr: 0x1000,
			userLen: uint32(len(pointers)),
			data:    pointers,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     handler.AioSubmitIocbPayloadArgBase,
			userPtr: 0x2000,
			userLen: aioPayloadIocbSize,
			data:    iocb0,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     handler.AioSubmitIocbPayloadArgBase + 1,
			userPtr: 0x3000,
			userLen: aioPayloadIocbSize,
			data:    iocb1,
		},
	)

	sections := aioJSONPayloadSections(t, "io_submit", bpfEventTypeEnter, args, 0, payload)
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertAioJSONSection(t, sections[0], "struct", "in", 2, 0x1000, pointers)
	assertAioJSONSection(t, sections[1], "struct", "in", handler.AioSubmitIocbPayloadArgBase, 0x2000, iocb0)
	assertAioJSONSection(t, sections[2], "struct", "in", handler.AioSubmitIocbPayloadArgBase+1, 0x3000, iocb1)
}

func TestJSONSyscallEventIncludesAioGeteventsPayloadSection(t *testing.T) {
	events := aioTestIoEventData(0x11, 0x22, 3, 4)
	args := [6]uint64{0xabc, 0, 1, 0x7000}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     3,
			userPtr: 0x7000,
			userLen: uint32(len(events)),
			data:    events,
		},
	)

	sections := aioJSONPayloadSections(t, "io_getevents", bpfEventTypeExit, args, 1, payload)
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	assertAioJSONSection(t, sections[0], "struct", "out", 3, 0x7000, events)
}

func TestJSONSyscallEventIncludesAioPgeteventsPayloadSections(t *testing.T) {
	timeout := aioTestTimespecData(5, 6)
	sigset := append(aioTestPointerBytes(0x6000), aioTestPointerBytes(8)...)
	mask := aioTestPointerBytes(1)
	args := [6]uint64{0xabc, 0, 0, 0, 0x4000, 0x5000}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     4,
			userPtr: 0x4000,
			userLen: uint32(len(timeout)),
			data:    timeout,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     5,
			userPtr: 0x5000,
			userLen: uint32(len(sigset)),
			data:    sigset,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     5,
			userPtr: 0x6000,
			userLen: uint32(len(mask)),
			data:    mask,
		},
	)

	sections := aioJSONPayloadSections(t, "io_pgetevents", bpfEventTypeEnter, args, 0, payload)
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertAioJSONSection(t, sections[0], "struct", "in", 4, 0x4000, timeout)
	assertAioJSONSection(t, sections[1], "struct", "in", 5, 0x5000, sigset)
	assertAioJSONSection(t, sections[2], "bytes", "in", 5, 0x6000, mask)
}

func aioJSONPayloadSections(
	t *testing.T,
	name string,
	eventType uint16,
	args [6]uint64,
	ret int64,
	payload []byte,
) []jsonPayloadSection {
	t.Helper()
	ev := newJSONSyscallEventFromTLVForTest(t, name, eventType, args, ret, payload)
	return ev.PayloadSections
}

func assertAioJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	kind string,
	direction string,
	argIndex int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != direction || got.ArgIndex != argIndex {
		t.Fatalf("aio section metadata = %+v", got)
	}
	if got.UserPtr != userPtr {
		t.Fatalf("aio section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("aio section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("aio section data = %v, want %v", data, wantData)
	}
}

func aioTestPointerBytes(ptr uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, ptr)
	return data
}

func aioTestIocbData(opcode uint16, buf uint64, nbytes uint64) []byte {
	data := make([]byte, aioPayloadIocbSize)
	binary.LittleEndian.PutUint16(data[16:18], opcode)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[24:32], buf)
	binary.LittleEndian.PutUint64(data[32:40], nbytes)
	return data
}

func aioTestIoEventData(dataValue uint64, obj uint64, res uint64, res2 uint64) []byte {
	data := make([]byte, aioPayloadEventsElemSize)
	binary.LittleEndian.PutUint64(data[0:8], dataValue)
	binary.LittleEndian.PutUint64(data[8:16], obj)
	binary.LittleEndian.PutUint64(data[16:24], res)
	binary.LittleEndian.PutUint64(data[24:32], res2)
	return data
}

func aioTestTimespecData(sec uint64, nsec uint64) []byte {
	data := make([]byte, timespecPayloadStructSize)
	binary.LittleEndian.PutUint64(data[0:8], sec)
	binary.LittleEndian.PutUint64(data[8:16], nsec)
	return data
}
