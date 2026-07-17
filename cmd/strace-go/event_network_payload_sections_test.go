package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/meta"
)

func jsonSockaddrInet(port uint16, ip [4]byte) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], 2)
	binary.BigEndian.PutUint16(data[2:4], port)
	copy(data[4:8], ip[:])
	return data
}

func putJSONSocklen(eventRaw *bpfEvent, offset int, value uint32) {
	binary.LittleEndian.PutUint32(eventRaw.StrArg[offset:offset+4], value)
}

func TestJSONSyscallEventIncludesConnectSockaddrSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, 0x4000, 16},
		DataLen:       16,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], jsonSockaddrInet(80, [4]byte{127, 0, 0, 1}))

	scMeta := meta.Syscall{Name: "connect"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "struct" || section.Direction != "in" || section.ArgIndex != 1 ||
		section.UserPtr != 0x4000 || section.UserLen != 16 {
		t.Fatalf("connect sockaddr section = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); len(got) != 16 {
		t.Fatalf("connect sockaddr copied length = %d, want 16", len(got))
	}
}

func TestJSONSyscallEventIncludesSendtoBufferAndSockaddrSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, 0x2000, 3, 0, 0x4000, 16},
		DataLen:       payloadMiscArgOffset + 16,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("abc"))
	copy(eventRaw.StrArg[payloadMiscArgOffset:], jsonSockaddrInet(80, [4]byte{127, 0, 0, 1}))

	scMeta := meta.Syscall{Name: "sendto"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	buf := ev.PayloadSections[0]
	addr := ev.PayloadSections[1]
	if buf.Kind != "bytes" || buf.Direction != "in" || buf.ArgIndex != 1 || buf.UserLen != 3 {
		t.Fatalf("sendto buffer section = %+v", buf)
	}
	if got := mustDecodeBase64(t, buf.DataBase64); string(got) != "abc" {
		t.Fatalf("sendto buffer data = %q, want abc", string(got))
	}
	if addr.Kind != "struct" || addr.Direction != "in" || addr.ArgIndex != 4 ||
		addr.UserPtr != 0x4000 || addr.UserLen != 16 {
		t.Fatalf("sendto sockaddr section = %+v", addr)
	}
}

func TestJSONSyscallEventIncludesRecvfromBufferSockaddrAndLenSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x2000, 5, 0, 0x4000, 0x5000},
		Ret:           3,
		DataLen:       recvfromSockaddrOffset + 16,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	putJSONSocklen(eventRaw, sockaddrLenEnterOffset, 16)
	copy(eventRaw.StrArg[payloadExitArgOffset:], []byte("abc"))
	putJSONSocklen(eventRaw, sockaddrLenExitOffset, 16)
	copy(eventRaw.StrArg[recvfromSockaddrOffset:], jsonSockaddrInet(80, [4]byte{127, 0, 0, 1}))

	scMeta := meta.Syscall{Name: "recvfrom"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 4 {
		t.Fatalf("PayloadSections = %d, want 4", len(ev.PayloadSections))
	}
	inLen := ev.PayloadSections[0]
	buf := ev.PayloadSections[1]
	addr := ev.PayloadSections[2]
	outLen := ev.PayloadSections[3]
	if inLen.Kind != "bytes" || inLen.Direction != "in" || inLen.ArgIndex != 5 {
		t.Fatalf("recvfrom in addrlen section = %+v", inLen)
	}
	if buf.Kind != "bytes" || buf.Direction != "out" || buf.ArgIndex != 1 || buf.UserLen != 3 {
		t.Fatalf("recvfrom buffer section = %+v", buf)
	}
	if addr.Kind != "struct" || addr.Direction != "out" || addr.ArgIndex != 4 ||
		addr.UserLen != 16 {
		t.Fatalf("recvfrom sockaddr section = %+v", addr)
	}
	if outLen.Kind != "bytes" || outLen.Direction != "out" || outLen.ArgIndex != 5 {
		t.Fatalf("recvfrom out addrlen section = %+v", outLen)
	}
}

func TestJSONSyscallEventIncludesAcceptSockaddrAndLenSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x4000, 0x5000},
		Ret:           4,
		DataLen:       payloadExitArgOffset + 16,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	putJSONSocklen(eventRaw, sockaddrLenEnterOffset, 16)
	putJSONSocklen(eventRaw, sockaddrLenExitOffset, 16)
	copy(eventRaw.StrArg[payloadExitArgOffset:], jsonSockaddrInet(80, [4]byte{127, 0, 0, 1}))

	scMeta := meta.Syscall{Name: "accept"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(ev.PayloadSections))
	}
	inLen := ev.PayloadSections[0]
	addr := ev.PayloadSections[1]
	outLen := ev.PayloadSections[2]
	if inLen.Kind != "bytes" || inLen.Direction != "in" || inLen.ArgIndex != 2 {
		t.Fatalf("accept in addrlen section = %+v", inLen)
	}
	if addr.Kind != "struct" || addr.Direction != "out" || addr.ArgIndex != 1 ||
		addr.UserPtr != 0x4000 || addr.UserLen != 16 {
		t.Fatalf("accept sockaddr section = %+v", addr)
	}
	if outLen.Kind != "bytes" || outLen.Direction != "out" || outLen.ArgIndex != 2 {
		t.Fatalf("accept out addrlen section = %+v", outLen)
	}
}
