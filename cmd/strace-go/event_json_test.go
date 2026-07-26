package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesWritePayloadSection(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     1,
		userPtr: 0x2000,
		userLen: 5,
		data:    []byte("hello"),
	})
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         1,
		EventVersion:  2,
		EventType:     bpfEventTypeEnter,
		EventFlags:    bpfEventFlagPayloadTLV | bpfEventFlagGenericEnter,
		Args:          [6]uint64{1, 0x2000, 5},
		DataLen:       uint32(len(payload)),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "write"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != 1 {
		t.Fatalf("write section metadata = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != "hello" {
		t.Fatalf("write section data = %q, want hello", string(got))
	}
}

func TestJSONSyscallEventIncludesReadPayloadSection(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     1,
		flags:   payloadTLVFlagDirectionOut,
		userPtr: 0x3000,
		userLen: 4,
		data:    []byte("data"),
	})
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         0,
		EventVersion:  2,
		EventType:     bpfEventTypeExit,
		EventFlags:    bpfEventFlagPayloadTLV,
		Args:          [6]uint64{3, 0x3000, 16},
		Ret:           4,
		DataLen:       uint32(len(payload)),
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "read"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "bytes" || section.Direction != "out" || section.ArgIndex != 1 {
		t.Fatalf("read section metadata = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != "data" {
		t.Fatalf("read section data = %q, want data", string(got))
	}
}

func TestJSONPayloadSectionOmitsWindowOffset(t *testing.T) {
	sections := jsonPayloadSections([]handler.PayloadSection{{
		Kind:      handler.PayloadKindBytes,
		Direction: handler.PayloadDirectionOut,
		ArgIndex:  1,
		UserPtr:   0x3000,
		UserLen:   1,
		CopiedLen: 1,
		ProbeRet:  0,
		Data:      []byte("x"),
	}})
	if len(sections) != 1 {
		t.Fatalf("jsonPayloadSections = %d, want 1", len(sections))
	}
	encoded, err := json.Marshal(sections[0])
	if err != nil {
		t.Fatalf("marshal json payload section: %v", err)
	}
	if bytes.Contains(encoded, []byte("offset")) {
		t.Fatalf("json payload section leaks fixed-window offset: %s", encoded)
	}
}

func TestIovecUserLenClampsOverflow(t *testing.T) {
	if got := iovecUserLen(2); got != 32 {
		t.Fatalf("iovecUserLen(2) = %d, want 32", got)
	}
	if got := iovecUserLen(^uint64(0)); got != ^uint32(0) {
		t.Fatalf("iovecUserLen(max) = %d, want uint32 max", got)
	}
}

func mustDecodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return data
}
