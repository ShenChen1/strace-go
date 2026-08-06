package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestPayloadSectionsForEventUsesTLVSections(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("tlv.txt\x00"),
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{rawAtFdcwd, 0x1000, 0},
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "openat"})

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

func TestPayloadSectionsForRawPayloadEventUsesTLVSections(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("tlv.txt\x00"),
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{rawAtFdcwd, 0x1000, 0},
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "openat"})

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

func TestPayloadSectionsForRawPayloadEventUsesStructTLVSection(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: 16,
		data:    timeJSONStruct(9, 10),
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{0, 0x2000},
		ret:        0,
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "clock_gettime"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindStruct || section.Direction != handler.PayloadDirectionOut ||
		section.ArgIndex != 1 || section.UserPtr != 0x2000 || section.UserLen != 16 {
		t.Fatalf("TLV struct section metadata = %+v", section)
	}
	if !bytes.Equal(section.Data, timeJSONStruct(9, 10)) {
		t.Fatalf("TLV struct section data = %v", section.Data)
	}
}

func TestPayloadSectionsForRawPayloadEventUsesCmsgTLVSection(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindCmsg,
		arg:     1,
		userPtr: 0x5000,
		userLen: 24,
		data:    bytes.Repeat([]byte{0xc3}, 24),
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{3, 0x1000, 0},
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "sendmsg"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindCmsg || section.Direction != handler.PayloadDirectionIn ||
		section.ArgIndex != 1 || section.UserPtr != 0x5000 || section.UserLen != 24 {
		t.Fatalf("CMSG section metadata = %+v", section)
	}
	if !bytes.Equal(section.Data, bytes.Repeat([]byte{0xc3}, 24)) {
		t.Fatalf("CMSG section data = %v", section.Data)
	}
}

func TestPayloadSectionsForRawPayloadEventUsesStatTLVSection(t *testing.T) {
	statData := bytes.Repeat([]byte{0x42}, statPayloadStructSize)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: statPayloadStructSize,
		data:    statData,
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{3, 0x2000},
		ret:        0,
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "fstat"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindStruct || section.Direction != handler.PayloadDirectionOut ||
		section.ArgIndex != 1 || section.UserPtr != 0x2000 || section.UserLen != statPayloadStructSize {
		t.Fatalf("stat section metadata = %+v", section)
	}
	if !bytes.Equal(section.Data, statData) {
		t.Fatalf("stat section data = %v", section.Data)
	}
}

func TestPayloadSectionsForRawPayloadEventUsesStatfsTLVSection(t *testing.T) {
	statfsData := bytes.Repeat([]byte{0x24}, statfsPayloadStructSize)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: statfsPayloadStructSize,
		data:    statfsData,
	})
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{3, 0x2000},
		ret:        0,
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "fstatfs"})

	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindStruct || section.Direction != handler.PayloadDirectionOut ||
		section.ArgIndex != 1 || section.UserPtr != 0x2000 || section.UserLen != statfsPayloadStructSize {
		t.Fatalf("statfs section metadata = %+v", section)
	}
	if !bytes.Equal(section.Data, statfsData) {
		t.Fatalf("statfs section data = %v", section.Data)
	}
}

func TestPayloadSectionsForRawPayloadEventUsesMultipleStructTLVSections(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     0,
		userPtr: 0x1000,
		userLen: 16,
		data:    timeJSONStruct(3, 4),
	})
	payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: 8,
		data:    timeJSONTimezone(5, 6),
	})...)
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{0x1000, 0x2000},
		ret:        0,
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "gettimeofday"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want timeval and timezone TLV sections", len(sections))
	}
	timeval := sections[0]
	if timeval.Kind != handler.PayloadKindStruct || timeval.Direction != handler.PayloadDirectionOut ||
		timeval.ArgIndex != 0 || timeval.UserPtr != 0x1000 || timeval.UserLen != 16 {
		t.Fatalf("timeval section metadata = %+v", timeval)
	}
	if !bytes.Equal(timeval.Data, timeJSONStruct(3, 4)) {
		t.Fatalf("timeval section data = %v", timeval.Data)
	}
	timezone := sections[1]
	if timezone.Kind != handler.PayloadKindStruct || timezone.Direction != handler.PayloadDirectionOut ||
		timezone.ArgIndex != 1 || timezone.UserPtr != 0x2000 || timezone.UserLen != 8 {
		t.Fatalf("timezone section metadata = %+v", timezone)
	}
	if !bytes.Equal(timezone.Data, timeJSONTimezone(5, 6)) {
		t.Fatalf("timezone section data = %v", timezone.Data)
	}
}

func TestPayloadSectionsForEventUsesExecTLVSections(t *testing.T) {
	snapshot := execJSONSnapshot()
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindExecArgs,
		arg:     1,
		userPtr: 0x2000,
		userLen: uint32(len(snapshot)),
		data:    snapshot,
	})
	payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: 0x1000,
		userLen: 10,
		data:    []byte("/bin/true\x00"),
	})...)
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{0x1000, 0x2000, 0x3000},
		data:       payload,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "execve"})

	if len(sections) != 2 {
		t.Fatalf("sections = %d, want exec args and filename sections", len(sections))
	}
	execSection := sections[0]
	if execSection.Kind != handler.PayloadKindExecArgs || execSection.ArgIndex != 1 ||
		execSection.UserPtr != 0x2000 || !bytes.Equal(execSection.Data, snapshot) {
		t.Fatalf("exec section = %+v, want argv snapshot", execSection)
	}
	pathSection := sections[1]
	if pathSection.Kind != handler.PayloadKindString || pathSection.ArgIndex != 0 ||
		pathSection.UserPtr != 0x1000 || !bytes.Equal(pathSection.Data, []byte("/bin/true\x00")) {
		t.Fatalf("path section = %+v, want filename snapshot", pathSection)
	}
}

func TestPayloadSectionsForEventDoesNotUseFixedExecSnapshot(t *testing.T) {
	snapshot := execJSONSnapshot()
	raw := rawPayloadEvent{
		valid:         true,
		eventType:     bpfEventTypeEnter,
		args:          [6]uint64{0x1000, 0x2000, 0x3000},
		probeRetEnter: 0,
		data:          snapshot,
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "execve"})

	if len(sections) != 0 {
		t.Fatalf("sections = %d, want no fixed exec snapshot fallback", len(sections))
	}
}

func TestPayloadSectionsForEventDoesNotUseFixedReadWritePayload(t *testing.T) {
	tests := []struct {
		name string
		raw  rawPayloadEvent
	}{
		{
			name: "write",
			raw: rawPayloadEvent{
				valid:         true,
				eventType:     bpfEventTypeEnter,
				args:          [6]uint64{1, 0x2000, 5},
				probeRetEnter: 0,
				data:          []byte("data"),
			},
		},
		{
			name: "pwrite64",
			raw: rawPayloadEvent{
				valid:         true,
				eventType:     bpfEventTypeEnter,
				args:          [6]uint64{1, 0x2000, 5, 0},
				probeRetEnter: 0,
				data:          []byte("data"),
			},
		},
		{
			name: "read",
			raw: rawPayloadEvent{
				valid:        true,
				eventType:    bpfEventTypeExit,
				args:         [6]uint64{3, 0x3000, 16},
				ret:          4,
				probeRetExit: 0,
				data:         []byte("data"),
			},
		},
		{
			name: "pread64",
			raw: rawPayloadEvent{
				valid:        true,
				eventType:    bpfEventTypeExit,
				args:         [6]uint64{3, 0x3000, 16, 0},
				ret:          4,
				probeRetExit: 0,
				data:         []byte("data"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sections := payloadSectionsForRawPayloadEvent(tt.raw, meta.Syscall{Name: tt.name})
			if len(sections) != 0 {
				t.Fatalf("sections = %d, want no fixed %s payload fallback", len(sections), tt.name)
			}
		})
	}
}

func TestPayloadSectionsForEventDoesNotFallbackOnInvalidTLV(t *testing.T) {
	raw := rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		args:       [6]uint64{rawAtFdcwd, 0x1000, 0},
		ret:        3,
		data:       []byte{0xff, 0xff, 0, 0},
	}

	sections := payloadSectionsForRawPayloadEvent(raw, meta.Syscall{Name: "openat"})

	if len(sections) != 0 {
		t.Fatalf("sections = %d, want no fixed fallback for invalid TLV", len(sections))
	}
}
