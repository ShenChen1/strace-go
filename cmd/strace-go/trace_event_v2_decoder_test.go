package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf/ringbuf"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

func TestDecodeTraceEventV2EnterEnvelope(t *testing.T) {
	sysID := syscallIDByName(t, "openat")
	args := [6]uint64{rawAtFdcwd, 0x1000, 0}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("v2.txt\x00"),
	})
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     101,
		tid:     102,
		sysID:   sysID,
		flags:   bpfEventFlagPayloadTLV,
		tsNs:    900,
		args:    args,
		payload: payload,
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a valid enter sample")
	}
	if !envelope.valid || envelope.eventVersion != traceEventV2Version || envelope.eventType != bpfEventTypeEnter {
		t.Fatalf("enter envelope = %+v, want valid v2 enter", envelope)
	}
	if envelope.pid != 101 || envelope.tid != 102 || envelope.sysID != sysID || envelope.enterTime != 900 {
		t.Fatalf("enter envelope identity = %+v", envelope)
	}
	if envelope.eventFlags&bpfEventFlagGenericEnter == 0 || envelope.eventFlags&bpfEventFlagPayloadTLV == 0 {
		t.Fatalf("enter event flags = %#x, want generic enter and TLV", envelope.eventFlags)
	}
	if envelope.args != args {
		t.Fatalf("enter args = %+v, want %+v", envelope.args, args)
	}
	assertTraceEventV2PathSection(t, envelope.payload)
}

func TestTraceRingbufRecordDecoderAcceptsTraceEventV2Sample(t *testing.T) {
	sysID := syscallIDByName(t, "openat")
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("v2.txt\x00"),
	})
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     101,
		tid:     102,
		sysID:   sysID,
		flags:   bpfEventFlagPayloadTLV,
		tsNs:    900,
		args:    [6]uint64{rawAtFdcwd, 0x1000},
		payload: payload,
	})

	envelope, ok := traceRingbufRecordDecoder{}.Decode(&ringbuf.Record{RawSample: raw})
	if !ok {
		t.Fatal("record decoder rejected a valid v2 sample")
	}
	assertTraceEventV2PathSection(t, envelope.payload)
}

func TestTraceEventV2OpenatExitMatchesPathFilter(t *testing.T) {
	sysID := syscallIDByName(t, "openat")
	args := [6]uint64{rawAtFdcwd, 0x1000, 0}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("v2.txt\x00"),
	})
	enterRaw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     101,
		tid:     101,
		sysID:   sysID,
		flags:   bpfEventFlagPayloadTLV,
		tsNs:    900,
		args:    args,
		payload: payload,
	})
	exitRaw := traceEventV2ExitSample(t, traceEventV2SampleSpec{
		pid:      101,
		tid:      101,
		sysID:    sysID,
		tsNs:     950,
		duration: 50,
		ret:      -2,
		args:     args,
	})

	state := newTraceState()
	enterEnvelope, ok := decodeTraceEventV2Envelope(enterRaw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected enter")
	}
	state.handleEnvelope(enterEnvelope)
	exitEnvelope, ok := decodeTraceEventV2Envelope(exitRaw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected exit")
	}
	update := state.handleEnvelope(exitEnvelope)
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"-e", "trace=openat", "-P", "v2.txt", "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
	}

	ev := newSyscallEventContextFromView(session, update.syscallView, 101, update.pendingEnter, update.payloadSections)

	if !ev.shouldOutput() {
		t.Fatalf("v2 openat exit did not match -P from pending payload: view=%+v pending=%+v", update.syscallView, update.pendingEnter)
	}
	if ev.pathText != `"v2.txt"` {
		t.Fatalf("pathText = %q, want quoted BPF snapshot", ev.pathText)
	}
}

func TestDecodeTraceEventV2ExitEnvelope(t *testing.T) {
	sysID := syscallIDByName(t, "read")
	args := [6]uint64{3, 0x2000, 16}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: 4,
		data:    []byte("data"),
	})
	raw := traceEventV2ExitSample(t, traceEventV2SampleSpec{
		pid:      201,
		tid:      202,
		sysID:    sysID,
		flags:    bpfEventFlagPayloadTLV,
		tsNs:     1000,
		duration: 55,
		ret:      4,
		args:     args,
		payload:  payload,
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a valid exit sample")
	}
	if envelope.ret != 4 || envelope.duration != 55 || envelope.enterTime != 945 {
		t.Fatalf("exit result fields = ret %d duration %d enter %d", envelope.ret, envelope.duration, envelope.enterTime)
	}
	if len(envelope.payload) != 1 || envelope.payload[0].Direction != handler.PayloadDirectionOut ||
		!bytes.Equal(envelope.payload[0].Data, []byte("data")) {
		t.Fatalf("exit payload = %+v, want OUT bytes section", envelope.payload)
	}
}

func TestDecodeTraceEventV2FallsBackToWindowPayload(t *testing.T) {
	sysID := syscallIDByName(t, "chdir")
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     301,
		tid:     302,
		sysID:   sysID,
		tsNs:    700,
		args:    [6]uint64{0x3000},
		payload: []byte("v2-fixed.txt\x00"),
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a fixed-window payload sample")
	}
	if envelope.eventFlags&bpfEventFlagPayloadTLV != 0 {
		t.Fatalf("event flags = %#x, want no inferred TLV flag", envelope.eventFlags)
	}
	if len(envelope.payload) != 1 || envelope.payload[0].ArgIndex != 0 ||
		!bytes.Equal(envelope.payload[0].Data, []byte("v2-fixed.txt\x00")) {
		t.Fatalf("window payload sections = %+v, want chdir path section", envelope.payload)
	}
}

func TestDecodeTraceEventV2RejectsShortCapture(t *testing.T) {
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:   101,
		tid:   102,
		sysID: 39,
		tsNs:  900,
	})
	bodyOffset := traceEventV2HeaderLen
	binary.LittleEndian.PutUint32(raw[bodyOffset+48:bodyOffset+52], 1)

	if _, ok := decodeTraceEventV2Envelope(raw); ok {
		t.Fatal("decodeTraceEventV2Envelope accepted a capture_len beyond the sample body")
	}
}

func assertTraceEventV2PathSection(t *testing.T, sections []handler.PayloadSection) {
	t.Helper()
	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindString || section.Direction != handler.PayloadDirectionIn ||
		section.ArgIndex != 1 || section.UserPtr != 0x1000 || section.UserLen != 9 {
		t.Fatalf("path section metadata = %+v", section)
	}
	if !bytes.Equal(section.Data, []byte("v2.txt\x00")) {
		t.Fatalf("path section data = %q", section.Data)
	}
}

type traceEventV2SampleSpec struct {
	eventType uint16
	pid       uint32
	tid       uint32
	sysID     uint32
	flags     uint32
	tsNs      uint64
	duration  uint64
	ret       int64
	args      [6]uint64
	payload   []byte
}

func traceEventV2EnterSample(t *testing.T, spec traceEventV2SampleSpec) []byte {
	t.Helper()
	size := traceEventV2HeaderLen + traceEventV2EnterBodyLen + len(spec.payload)
	spec.eventType = bpfEventTypeEnter
	raw := traceEventV2HeaderSample(spec, size)
	bodyOffset := traceEventV2HeaderLen
	putTraceEventV2Args(raw[bodyOffset:bodyOffset+48], spec.args)
	binary.LittleEndian.PutUint32(raw[bodyOffset+48:bodyOffset+52], uint32(len(spec.payload)))
	copy(raw[bodyOffset+traceEventV2EnterBodyLen:], spec.payload)
	return raw
}

func traceEventV2ExitSample(t *testing.T, spec traceEventV2SampleSpec) []byte {
	t.Helper()
	size := traceEventV2HeaderLen + traceEventV2ExitBodyLen + len(spec.payload)
	spec.eventType = bpfEventTypeExit
	raw := traceEventV2HeaderSample(spec, size)
	bodyOffset := traceEventV2HeaderLen
	binary.LittleEndian.PutUint64(raw[bodyOffset:bodyOffset+8], uint64(spec.ret))
	binary.LittleEndian.PutUint64(raw[bodyOffset+8:bodyOffset+16], spec.duration)
	putTraceEventV2Args(raw[bodyOffset+16:bodyOffset+64], spec.args)
	binary.LittleEndian.PutUint32(raw[bodyOffset+64:bodyOffset+68], uint32(len(spec.payload)))
	copy(raw[bodyOffset+traceEventV2ExitBodyLen:], spec.payload)
	return raw
}

func traceEventV2HeaderSample(spec traceEventV2SampleSpec, size int) []byte {
	raw := make([]byte, size)
	binary.LittleEndian.PutUint16(raw[0:2], traceEventV2Version)
	binary.LittleEndian.PutUint16(raw[2:4], spec.eventType)
	binary.LittleEndian.PutUint16(raw[4:6], uint16(spec.flags))
	binary.LittleEndian.PutUint16(raw[6:8], traceEventV2HeaderLen)
	binary.LittleEndian.PutUint32(raw[8:12], uint32(size))
	binary.LittleEndian.PutUint32(raw[12:16], spec.pid)
	binary.LittleEndian.PutUint32(raw[16:20], spec.tid)
	binary.LittleEndian.PutUint32(raw[20:24], spec.sysID)
	binary.LittleEndian.PutUint64(raw[32:40], spec.tsNs)
	return raw
}

func putTraceEventV2Args(data []byte, args [6]uint64) {
	for i, arg := range args {
		binary.LittleEndian.PutUint64(data[i*8:i*8+8], arg)
	}
}
