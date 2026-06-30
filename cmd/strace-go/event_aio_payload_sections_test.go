package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesAioSetupPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{128, 0x1000},
		Ret:           0,
		DataLen:       handler.BpfExitArgOffset + aioPayloadPointerSize,
		ProbeRetExit:  0,
		ProbeRetEnter: -1,
	}
	copy(eventRaw.StrArg[handler.BpfExitArgOffset:], aioTestPointerBytes(0xabc))

	sections := aioJSONPayloadSections(t, eventRaw, "io_setup")
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	assertAioJSONSection(t, sections[0], "struct", "out", 1, handler.BpfExitArgOffset, 0x1000, aioTestPointerBytes(0xabc))
}

func TestJSONSyscallEventIncludesAioSubmitPayloadSections(t *testing.T) {
	iocb0 := aioTestIocbData(1, 0x4000, 3)
	iocb1 := aioTestIocbData(0, 0x5000, 4)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0xabc, 2, 0x1000},
		DataLen:       handler.BpfMiscArgOffset + 2*aioPayloadIocbSize,
		ProbeRetEnter: 0,
	}
	pointers := append(aioTestPointerBytes(0x2000), aioTestPointerBytes(0x3000)...)
	copy(eventRaw.StrArg[:], pointers)
	copy(eventRaw.StrArg[handler.BpfMiscArgOffset:], iocb0)
	copy(eventRaw.StrArg[handler.BpfMiscArgOffset+aioPayloadIocbSize:], iocb1)

	sections := aioJSONPayloadSections(t, eventRaw, "io_submit")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertAioJSONSection(t, sections[0], "struct", "in", 2, handler.BpfEnterArgOffset, 0x1000, pointers)
	assertAioJSONSection(t, sections[1], "struct", "in", handler.AioSubmitIocbPayloadArgBase, handler.BpfMiscArgOffset, 0x2000, iocb0)
	assertAioJSONSection(t, sections[2], "struct", "in", handler.AioSubmitIocbPayloadArgBase+1, handler.BpfMiscArgOffset+aioPayloadIocbSize, 0x3000, iocb1)
}

func TestJSONSyscallEventIncludesAioGeteventsPayloadSection(t *testing.T) {
	events := aioTestIoEventData(0x11, 0x22, 3, 4)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0xabc, 0, 1, 0x7000},
		Ret:           1,
		DataLen:       handler.BpfExitArgOffset + aioPayloadEventsElemSize,
		ProbeRetExit:  0,
		ProbeRetEnter: -1,
	}
	copy(eventRaw.StrArg[handler.BpfExitArgOffset:], events)

	sections := aioJSONPayloadSections(t, eventRaw, "io_getevents")
	if len(sections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(sections))
	}
	assertAioJSONSection(t, sections[0], "struct", "out", 3, handler.BpfExitArgOffset, 0x7000, events)
}

func TestJSONSyscallEventIncludesAioPgeteventsPayloadSections(t *testing.T) {
	timeout := aioTestTimespecData(5, 6)
	sigset := append(aioTestPointerBytes(0x6000), aioTestPointerBytes(8)...)
	mask := aioTestPointerBytes(1)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0xabc, 0, 0, 0, 0x4000, 0x5000},
		DataLen:       aioPayloadSigmaskOffset + uint32(len(mask)),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[handler.BpfMiscArgOffset:], timeout)
	copy(eventRaw.StrArg[aioPayloadSigsetOffset:], sigset)
	copy(eventRaw.StrArg[aioPayloadSigmaskOffset:], mask)

	sections := aioJSONPayloadSections(t, eventRaw, "io_pgetevents")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertAioJSONSection(t, sections[0], "struct", "in", 4, handler.BpfMiscArgOffset, 0x4000, timeout)
	assertAioJSONSection(t, sections[1], "struct", "in", 5, aioPayloadSigsetOffset, 0x5000, sigset)
	assertAioJSONSection(t, sections[2], "bytes", "in", 5, aioPayloadSigmaskOffset, 0x6000, mask)
}

func aioJSONPayloadSections(t *testing.T, eventRaw *bpfEvent, name string) []jsonPayloadSection {
	t.Helper()
	scMeta := meta.Syscall{Name: name}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	return ev.PayloadSections
}

func assertAioJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	kind string,
	direction string,
	argIndex int,
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != direction || got.ArgIndex != argIndex {
		t.Fatalf("aio section metadata = %+v", got)
	}
	if got.Offset != uint32(offset) || got.UserPtr != userPtr {
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
