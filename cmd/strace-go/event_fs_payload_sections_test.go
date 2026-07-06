package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesMountPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000, 0, 0x4000},
		DataLen:       mountDataOffset + mountStringMaxBytes,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[mountSourceOffset:], []byte("/dev/sda1\x00"))
	copy(eventRaw.StrArg[mountTargetOffset:], []byte("/mnt\x00"))
	copy(eventRaw.StrArg[mountTypeOffset:], []byte("ext4\x00"))
	copy(eventRaw.StrArg[mountDataOffset:], []byte("rw\x00"))

	scMeta := meta.Syscall{Name: "mount"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 0, offset: mountSourceOffset, userPtr: 0x1000, kind: "string", direction: "in", data: "/dev/sda1\x00"},
		{argIndex: 1, offset: mountTargetOffset, userPtr: 0x2000, kind: "string", direction: "in", data: "/mnt\x00"},
		{argIndex: 2, offset: mountTypeOffset, userPtr: 0x3000, kind: "string", direction: "in", data: "ext4\x00"},
		{argIndex: 4, offset: mountDataOffset, userPtr: 0x4000, kind: "string", direction: "in", data: "rw\x00"},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesFsconfigPayloadSections(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
		data []byte
		want []wantFsJSONPayloadSection
	}{
		{
			name: "string",
			args: [6]uint64{3, 1, 0x1000, 0x2000, 0},
			data: append(fsPayloadData("key\x00", fsconfigValueOffset), []byte("value\x00")...),
			want: []wantFsJSONPayloadSection{
				{argIndex: 2, offset: fsconfigKeyOffset, userPtr: 0x1000, kind: "string", direction: "in", data: "key\x00"},
				{argIndex: 3, offset: fsconfigValueOffset, userPtr: 0x2000, kind: "string", direction: "in", data: "value\x00"},
			},
		},
		{
			name: "binary",
			args: [6]uint64{3, 2, 0x1000, 0x2000, 3},
			data: append(fsPayloadData("blob\x00", fsconfigValueOffset), []byte{1, 2, 3}...),
			want: []wantFsJSONPayloadSection{
				{argIndex: 2, offset: fsconfigKeyOffset, userPtr: 0x1000, kind: "string", direction: "in", data: "blob\x00"},
				{argIndex: 3, offset: fsconfigValueOffset, userPtr: 0x2000, kind: "bytes", direction: "in", data: string([]byte{1, 2, 3})},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          tt.args,
				DataLen:       uint32(len(tt.data)),
				ProbeRetEnter: 0,
			}
			copy(eventRaw.StrArg[:], tt.data)

			scMeta := meta.Syscall{Name: "fsconfig"}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			assertFsJSONPayloadSections(t, ev.PayloadSections, tt.want)
		})
	}
}

func TestJSONSyscallEventIncludesUmountPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000},
		DataLen:       6,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("/mnt\x00"))

	scMeta := meta.Syscall{Name: "umount2"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 0, offset: 0, userPtr: 0x1000, kind: "string", direction: "in", data: "/mnt\x00"},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestJSONSyscallEventIncludesGetdentsPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:    bpfEventTypeExit,
		Args:         [6]uint64{3, 0x3000, 512},
		Ret:          16,
		DataLen:      uint32(handler.BpfExitArgOffset + 16),
		ProbeRetExit: 0,
	}
	copy(eventRaw.StrArg[handler.BpfExitArgOffset:], []byte("dirent-section!!"))

	scMeta := meta.Syscall{Name: "getdents64"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	want := []wantFsJSONPayloadSection{
		{argIndex: 1, offset: handler.BpfExitArgOffset, userPtr: 0x3000, kind: "bytes", direction: "out", data: "dirent-section!!"},
	}
	assertFsJSONPayloadSections(t, ev.PayloadSections, want)
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareMountRule(t *testing.T) {
	args := [6]uint64{0x1000, 0x2000, 0x3000, 0, 0x4000}
	data := make([]byte, mountDataOffset+mountStringMaxBytes)
	copy(data[mountSourceOffset:], []byte("/dev/sda1\x00"))
	copy(data[mountTargetOffset:], []byte("/mnt\x00"))
	copy(data[mountTypeOffset:], []byte("ext4\x00"))
	copy(data[mountDataOffset:], []byte("rw\x00"))
	event := payloadEvent{
		raw: &bpfEvent{EventType: bpfEventTypeEnter, Args: args, ProbeRetEnter: 0},
		source: staticPayloadSource{
			args: args,
			data: data,
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "mount"})

	want := []wantFsPayloadSection{
		{argIndex: 0, offset: mountSourceOffset, userPtr: 0x1000, kind: handler.PayloadKindString, data: []byte("/dev/sda1\x00")},
		{argIndex: 1, offset: mountTargetOffset, userPtr: 0x2000, kind: handler.PayloadKindString, data: []byte("/mnt\x00")},
		{argIndex: 2, offset: mountTypeOffset, userPtr: 0x3000, kind: handler.PayloadKindString, data: []byte("ext4\x00")},
		{argIndex: 4, offset: mountDataOffset, userPtr: 0x4000, kind: handler.PayloadKindString, data: []byte("rw\x00")},
	}
	assertFsPayloadSections(t, sections, want)
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareFsconfigRules(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
		data []byte
		want []wantFsPayloadSection
	}{
		{
			name: "string",
			args: [6]uint64{3, 1, 0x1000, 0x2000, 0},
			data: append(fsPayloadData("key\x00", fsconfigValueOffset), []byte("value\x00")...),
			want: []wantFsPayloadSection{
				{argIndex: 2, offset: fsconfigKeyOffset, userPtr: 0x1000, kind: handler.PayloadKindString, data: []byte("key\x00")},
				{argIndex: 3, offset: fsconfigValueOffset, userPtr: 0x2000, kind: handler.PayloadKindString, data: []byte("value\x00")},
			},
		},
		{
			name: "binary",
			args: [6]uint64{3, 2, 0x1000, 0x2000, 3},
			data: append(fsPayloadData("blob\x00", fsconfigValueOffset), []byte{1, 2, 3}...),
			want: []wantFsPayloadSection{
				{argIndex: 2, offset: fsconfigKeyOffset, userPtr: 0x1000, kind: handler.PayloadKindString, data: []byte("blob\x00")},
				{argIndex: 3, offset: fsconfigValueOffset, userPtr: 0x2000, kind: handler.PayloadKindBytes, data: []byte{1, 2, 3}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := payloadEvent{
				raw: &bpfEvent{EventType: bpfEventTypeEnter, Args: tt.args, ProbeRetEnter: 0},
				source: staticPayloadSource{
					args: tt.args,
					data: tt.data,
				},
			}

			sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "fsconfig"})

			assertFsPayloadSections(t, sections, tt.want)
		})
	}
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareUmountRule(t *testing.T) {
	args := [6]uint64{0x1000}
	event := payloadEvent{
		raw: &bpfEvent{EventType: bpfEventTypeEnter, Args: args, ProbeRetEnter: 0},
		source: staticPayloadSource{
			args: args,
			data: []byte("/mnt\x00"),
		},
	}

	sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: "umount2"})

	want := []wantFsPayloadSection{
		{argIndex: 0, offset: mountSourceOffset, userPtr: 0x1000, kind: handler.PayloadKindString, data: []byte("/mnt\x00")},
	}
	assertFsPayloadSections(t, sections, want)
}

type wantFsJSONPayloadSection struct {
	argIndex  int
	offset    uint32
	userPtr   uint64
	kind      string
	direction string
	data      string
}

func assertFsJSONPayloadSections(t *testing.T, got []jsonPayloadSection, want []wantFsJSONPayloadSection) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertFsJSONPayloadSection(t, got[i], want[i])
	}
}

func assertFsJSONPayloadSection(t *testing.T, got jsonPayloadSection, want wantFsJSONPayloadSection) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("fs section metadata = %+v, want %+v", got, want)
	}
	if got.Offset != want.offset || got.UserPtr != want.userPtr {
		t.Fatalf("fs section bounds = %+v, want %+v", got, want)
	}
	if got.UserLen != uint32(len(want.data)) || got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("fs section lengths = %+v, want %d", got, len(want.data))
	}
	if data := mustDecodeBase64(t, got.DataBase64); string(data) != want.data {
		t.Fatalf("fs section data = %q, want %q", string(data), want.data)
	}
}

type wantFsPayloadSection struct {
	argIndex int
	offset   uint32
	userPtr  uint64
	kind     handler.PayloadKind
	data     []byte
}

func assertFsPayloadSections(t *testing.T, got []handler.PayloadSection, want []wantFsPayloadSection) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("sections = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertFsPayloadSection(t, got[i], want[i])
	}
}

func assertFsPayloadSection(t *testing.T, got handler.PayloadSection, want wantFsPayloadSection) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != handler.PayloadDirectionIn || got.ArgIndex != want.argIndex {
		t.Fatalf("fs section metadata = %+v, want %+v", got, want)
	}
	if got.Offset != want.offset || got.UserPtr != want.userPtr {
		t.Fatalf("fs section bounds = %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.Data, want.data) {
		t.Fatalf("fs section data = %v, want %v", got.Data, want.data)
	}
}

func fsPayloadData(prefix string, valueOffset int) []byte {
	data := make([]byte, valueOffset)
	copy(data, []byte(prefix))
	return data
}
