package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type staticPayloadSource struct {
	args [6]uint64
	data []byte
}

func (s staticPayloadSource) Arg(index int) (uint64, bool) {
	if index < 0 || index >= len(s.args) {
		return 0, false
	}
	return s.args[index], true
}

func (s staticPayloadSource) PayloadWindow(offset int, maxLen int) ([]byte, bool) {
	if offset < 0 || maxLen <= 0 || offset >= len(s.data) {
		return nil, false
	}
	end := offset + maxLen
	if end > len(s.data) {
		end = len(s.data)
	}
	return s.data[offset:end], true
}

func TestPayloadSectionFromSourceSpecUsesAbstractSource(t *testing.T) {
	source := staticPayloadSource{
		args: [6]uint64{0x1000, 0x2000},
		data: []byte("prefix-payload-suffix"),
	}

	sections := payloadSectionFromSourceSpec(source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  1,
		offset:    len("prefix-"),
		userLen:   uint32(len("payload-suffix")),
		maxLen:    uint32(len("payload")),
		probeRet:  0,
	})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindBytes || section.Direction != handler.PayloadDirectionIn {
		t.Fatalf("section type = %s/%s, want bytes/in", section.Kind, section.Direction)
	}
	if section.ArgIndex != 1 || section.UserPtr != 0x2000 {
		t.Fatalf("section arg metadata = arg %d ptr %#x, want arg 1 ptr 0x2000", section.ArgIndex, section.UserPtr)
	}
	if section.UserLen != uint32(len("payload-suffix")) || section.CopiedLen != uint32(len("payload")) {
		t.Fatalf("section lengths = user %d copied %d, want %d/%d",
			section.UserLen, section.CopiedLen, len("payload-suffix"), len("payload"))
	}
	if !bytes.Equal(section.Data, []byte("payload")) {
		t.Fatalf("section data = %q, want payload", section.Data)
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareWriteRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{1, 0x2000, 7},
		ProbeRetEnter: 0,
	}
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: []byte("payload-from-source"),
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "write"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.UserPtr != 0x2000 || section.UserLen != 7 || section.CopiedLen != 7 {
		t.Fatalf("section metadata = ptr %#x user %d copied %d, want ptr 0x2000 user/copy 7",
			section.UserPtr, section.UserLen, section.CopiedLen)
	}
	if !bytes.Equal(section.Data, []byte("payload")) {
		t.Fatalf("section data = %q, want payload from source", section.Data)
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareProcessVMIovecRule(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{123, 0x3000, 1, 0x4000, 1, 0},
		ProbeRetEnter: 0,
	}
	data := make([]byte, handler.BpfMiscArgOffset+16)
	copy(data[:16], []byte("local-iovec-0000"))
	copy(data[handler.BpfMiscArgOffset:], []byte("remote-iovec-000"))
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "process_vm_readv"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	local, remote := sections[0], sections[1]
	if local.Kind != handler.PayloadKindIovec || local.ArgIndex != 1 || local.UserPtr != 0x3000 || local.Offset != 0 {
		t.Fatalf("local section = %+v, want arg 1 iovec at offset 0", local)
	}
	if remote.Kind != handler.PayloadKindIovec || remote.ArgIndex != 3 ||
		remote.UserPtr != 0x4000 || remote.Offset != uint32(handler.BpfMiscArgOffset) {
		t.Fatalf("remote section = %+v, want arg 3 iovec at misc offset", remote)
	}
	if !bytes.Equal(local.Data, []byte("local-iovec-0000")) {
		t.Fatalf("local data = %q", local.Data)
	}
	if !bytes.Equal(remote.Data, []byte("remote-iovec-000")) {
		t.Fatalf("remote data = %q", remote.Data)
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareSimplePathFallback(t *testing.T) {
	raw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{^uint64(99), 0x5000},
		ProbeRetEnter: 0,
	}
	event := payloadEvent{
		raw: raw,
		source: staticPayloadSource{
			args: raw.Args,
			data: []byte("from-source\x00ignored"),
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "openat"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindString || section.ArgIndex != 1 || section.UserPtr != 0x5000 {
		t.Fatalf("path section metadata = %+v, want string arg 1 ptr 0x5000", section)
	}
	if !bytes.Equal(section.Data, []byte("from-source\x00")) {
		t.Fatalf("path data = %q, want nul-terminated source path", section.Data)
	}
}
