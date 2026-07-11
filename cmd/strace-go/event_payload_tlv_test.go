package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForEventUsesTLVSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       [6]uint64{rawAtFdcwd, 0x1000, 0},
		Ptr:        0x1000,
	}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("tlv.txt\x00"),
	})
	eventRaw.DataLen = uint32(len(payload))
	copy(eventRaw.StrArg[:], payload)

	sections := payloadSectionsForEvent(eventRaw, meta.Syscall{Name: "openat"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindString || section.Direction != handler.PayloadDirectionIn ||
		section.ArgIndex != 1 || section.UserPtr != 0x1000 || section.UserLen != 9 {
		t.Fatalf("TLV section metadata = %+v", section)
	}
	if !bytes.Equal(section.Data, []byte("tlv.txt\x00")) {
		t.Fatalf("TLV section data = %q", section.Data)
	}
}

func TestSyscallEventContextUsesTLVPathSection(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil, nil),
	}
	eventRaw := tlvOpenatEvent(t, []byte("from-tlv\x00"))

	ev := newSyscallEventContext(session, eventRaw, 101, nil)

	if ev.pathText != `"from-tlv"` {
		t.Fatalf("pathText = %q, want TLV snapshot path", ev.pathText)
	}
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !ok || !bytes.Equal(section.Data, []byte("from-tlv\x00")) {
		t.Fatalf("handler section = %+v, %v; want TLV path section", section, ok)
	}
}

func TestPayloadSectionsForEventDoesNotFallbackOnInvalidTLV(t *testing.T) {
	eventRaw := tlvOpenatEvent(t, []byte("fixed.txt\x00"))
	eventRaw.DataLen = 4
	copy(eventRaw.StrArg[:], []byte{0xff, 0xff, 0, 0})

	sections := payloadSectionsForEvent(eventRaw, meta.Syscall{Name: "openat"})

	if len(sections) != 0 {
		t.Fatalf("sections = %d, want no fixed fallback for invalid TLV", len(sections))
	}
}

type payloadTLVTestSection struct {
	kind     uint16
	arg      uint16
	flags    uint16
	userPtr  uint64
	userLen  uint32
	probeRet int32
	data     []byte
}

func tlvOpenatEvent(t *testing.T, path []byte) *bpfEvent {
	t.Helper()
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: uint32(len(path)),
		data:    path,
	})
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         syscallIDByName(t, "openat"),
		EventType:     bpfEventTypeExit,
		EventFlags:    bpfEventFlagPayloadTLV,
		Args:          [6]uint64{rawAtFdcwd, 0x1000, 0},
		Ptr:           0x1000,
		DataLen:       uint32(len(payload)),
		ProbeRetEnter: 0,
		Ret:           3,
	}
	copy(eventRaw.StrArg[:], payload)
	return eventRaw
}

func payloadTLVBytes(t *testing.T, section payloadTLVTestSection) []byte {
	t.Helper()
	if len(section.data) > len((&bpfEvent{}).StrArg)-payloadTLVHeaderSize {
		t.Fatal("test TLV section too large")
	}
	buf := make([]byte, payloadTLVHeaderSize+len(section.data))
	binary.LittleEndian.PutUint16(buf[0:2], section.kind)
	binary.LittleEndian.PutUint16(buf[2:4], section.arg)
	binary.LittleEndian.PutUint16(buf[4:6], section.flags)
	binary.LittleEndian.PutUint32(buf[8:12], section.userLen)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(section.data)))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(section.probeRet))
	binary.LittleEndian.PutUint64(buf[24:32], section.userPtr)
	copy(buf[payloadTLVHeaderSize:], section.data)
	return buf
}
