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

const (
	execPayloadSnapshotMagic      = 0x45584543
	execPayloadSnapshotHeaderSize = 32
	execPayloadArgSnapshotSize    = 56
	execPayloadArgSnapshotCount   = 48
	execPayloadEnvSnapshotCount   = 64
	execPayloadSnapshotSize       = execPayloadSnapshotHeaderSize +
		execPayloadArgSnapshotCount*execPayloadArgSnapshotSize +
		execPayloadEnvSnapshotCount*execPayloadArgSnapshotSize
)

func TestPayloadSectionsForEventUsesTLVSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       [6]uint64{rawAtFdcwd, 0x1000, 0},
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
	eventRaw := &bpfEvent{
		EventType:  bpfEventTypeEnter,
		EventFlags: bpfEventFlagPayloadTLV,
		Args:       [6]uint64{0x1000, 0x2000, 0x3000},
		DataLen:    uint32(len(payload)),
	}
	copy(eventRaw.StrArg[:], payload)

	sections := payloadSectionsForEvent(eventRaw, meta.Syscall{Name: "execve"})

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
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000},
		DataLen:       uint32(len(snapshot)),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], snapshot)

	sections := payloadSectionsForEvent(eventRaw, meta.Syscall{Name: "execve"})

	if len(sections) != 0 {
		t.Fatalf("sections = %d, want no fixed exec snapshot fallback", len(sections))
	}
}

func TestPayloadSectionsForEventDoesNotUseFixedReadWritePayload(t *testing.T) {
	tests := []struct {
		name     string
		eventRaw bpfEvent
	}{
		{
			name: "write",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{1, 0x2000, 5},
				DataLen:       5,
				ProbeRetEnter: 0,
			},
		},
		{
			name: "pwrite64",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{1, 0x2000, 5, 0},
				DataLen:       5,
				ProbeRetEnter: 0,
			},
		},
		{
			name: "read",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{3, 0x3000, 16},
				Ret:          4,
				DataLen:      4,
				ProbeRetExit: 0,
			},
		},
		{
			name: "pread64",
			eventRaw: bpfEvent{
				EventType:    bpfEventTypeExit,
				Args:         [6]uint64{3, 0x3000, 16, 0},
				Ret:          4,
				DataLen:      4,
				ProbeRetExit: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy(tt.eventRaw.StrArg[:], []byte("data"))
			sections := payloadSectionsForEvent(&tt.eventRaw, meta.Syscall{Name: tt.name})
			if len(sections) != 0 {
				t.Fatalf("sections = %d, want no fixed %s payload fallback", len(sections), tt.name)
			}
		})
	}
}

func TestSyscallEventContextUsesTLVPathSection(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
	}
	eventRaw := tlvOpenatEvent(t, []byte("from-tlv\x00"))

	ev := newSyscallEventContextFromBPF(session, eventRaw, 101, nil)

	section, ok := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !ok || !bytes.Equal(section.Data, []byte("from-tlv\x00")) {
		t.Fatalf("handler section = %+v, %v; want TLV path section", section, ok)
	}
	ev.updateFDState(session.fdStateStore())
	if got := session.fdStateStore().PathMap()["101:3"]; got != "from-tlv" {
		t.Fatalf("fd path = %q, want TLV snapshot path", got)
	}
}

func TestShouldEmitGenericEnterForPathFilter(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "text without path filter", args: []string{"-e", "trace=openat", "/bin/true"}, want: false},
		{name: "text with path filter", args: []string{"-e", "trace=openat", "-P", "from-tlv", "/bin/true"}, want: true},
		{name: "json", args: []string{"--event-format=json", "-e", "trace=openat", "/bin/true"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldEmitGenericEnter(cli.ParseArgs(tt.args)); got != tt.want {
				t.Fatalf("shouldEmitGenericEnter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSyscallEventContextMergesPendingEnterTLVPathForPathFilter(t *testing.T) {
	session := &traceSession{
		targetPid: 101,
		opts:      cli.ParseArgs([]string{"-e", "trace=openat", "-P", "from-tlv", "/bin/true"}),
		decoder:   event.NewDecoder(),
		fdState:   newFDStateStoreFromMaps(nil, nil),
		state:     newTraceState(),
	}
	enterRaw := tlvOpenatEvent(t, []byte("from-tlv\x00"))
	enterRaw.EventType = bpfEventTypeEnter
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         syscallIDByName(t, "openat"),
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{rawAtFdcwd, 0x1000, 0},
		ProbeRetEnter: 0,
		Ret:           -9,
	}
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections,
	)

	if !ev.shouldOutput() {
		t.Fatal("openat exit should match -P from-tlv using pending enter TLV path")
	}
	section, ok := ev.handlerContext.Section(1, handler.PayloadKindString)
	if !ok || !bytes.Equal(section.Data, []byte("from-tlv\x00")) {
		t.Fatalf("merged handler section = %+v, %v; want pending enter TLV path", section, ok)
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

func execJSONSnapshot() []byte {
	data := make([]byte, execPayloadSnapshotSize)
	binary.LittleEndian.PutUint32(data[0:4], execPayloadSnapshotMagic)
	binary.LittleEndian.PutUint16(data[4:6], 1)
	binary.LittleEndian.PutUint16(data[6:8], 1)
	return data
}
