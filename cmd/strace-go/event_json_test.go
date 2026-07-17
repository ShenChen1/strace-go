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

func TestJSONSyscallEventIncludesOutBufferPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		argIndex int
	}{
		{name: "getcwd", args: [6]uint64{0x3000, 32}, argIndex: 0},
		{name: "readlink", args: [6]uint64{0x2000, 0x3000, 32}, argIndex: 1},
		{name: "readlinkat", args: [6]uint64{^uint64(99), 0x2000, 0x3000, 32}, argIndex: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				Pid:           101,
				Tid:           101,
				EventVersion:  2,
				EventType:     bpfEventTypeExit,
				Args:          tt.args,
				Ret:           6,
				DataLen:       payloadExitArgOffset + 6,
				ProbeRetEnter: -1,
				ProbeRetExit:  0,
			}
			copy(eventRaw.StrArg[payloadExitArgOffset:], []byte("target"))

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			section := ev.PayloadSections[0]
			if section.Kind != "bytes" || section.Direction != "out" || section.ArgIndex != tt.argIndex {
				t.Fatalf("%s section metadata = %+v", tt.name, section)
			}
			if got := mustDecodeBase64(t, section.DataBase64); string(got) != "target" {
				t.Fatalf("%s section data = %q, want target", tt.name, string(got))
			}
		})
	}
}

func TestJSONSyscallEventIncludesStructPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		argIndex int
		size     int
		fill     byte
	}{
		{name: "stat", args: [6]uint64{0x1000, 0x2000}, argIndex: 1, size: statPayloadStructSize, fill: 0x11},
		{name: "lstat", args: [6]uint64{0x1000, 0x2000}, argIndex: 1, size: statPayloadStructSize, fill: 0x22},
		{name: "fstat", args: [6]uint64{3, 0x2000}, argIndex: 1, size: statPayloadStructSize, fill: 0x33},
		{name: "newfstatat", args: [6]uint64{^uint64(99), 0x1000, 0x2000}, argIndex: 2, size: statPayloadStructSize, fill: 0x44},
		{name: "statfs", args: [6]uint64{0x1000, 0x2000}, argIndex: 1, size: statfsPayloadStructSize, fill: 0x55},
		{name: "fstatfs", args: [6]uint64{3, 0x2000}, argIndex: 1, size: statfsPayloadStructSize, fill: 0x66},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantData := bytes.Repeat([]byte{tt.fill}, tt.size)
			eventRaw := &bpfEvent{
				Pid:           101,
				Tid:           101,
				EventVersion:  2,
				EventType:     bpfEventTypeExit,
				Args:          tt.args,
				Ret:           0,
				DataLen:       uint32(payloadExitArgOffset + tt.size),
				ProbeRetEnter: -1,
				ProbeRetExit:  0,
			}
			copy(eventRaw.StrArg[payloadExitArgOffset:], wantData)

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			section := ev.PayloadSections[0]
			if section.Kind != "struct" || section.Direction != "out" || section.ArgIndex != tt.argIndex {
				t.Fatalf("%s section metadata = %+v", tt.name, section)
			}
			if section.UserLen != uint32(tt.size) || section.CopiedLen != uint32(tt.size) {
				t.Fatalf("%s section bounds = %+v", tt.name, section)
			}
			if got := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(got, wantData) {
				t.Fatalf("%s section data length = %d, want %d", tt.name, len(got), len(wantData))
			}
		})
	}
}

func TestJSONSyscallEventSkipsStructPayloadSectionOnFailedStat(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x2000},
		Ret:           -2,
		DataLen:       payloadExitArgOffset + statPayloadStructSize,
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[payloadExitArgOffset:], bytes.Repeat([]byte{0x11}, statPayloadStructSize))

	scMeta := meta.Syscall{Name: "fstat"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 0 {
		t.Fatalf("PayloadSections = %+v, want none for failed fstat", ev.PayloadSections)
	}
}

func TestJSONSyscallEventIncludesPollStructPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x2000, 2, 1000},
		Ret:           1,
		DataLen:       payloadExitArgOffset + 16,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[:], []byte("pollfd-enter-000"))
	copy(eventRaw.StrArg[payloadExitArgOffset:], []byte("pollfd-exit--000"))

	scMeta := meta.Syscall{Name: "poll"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	enter := ev.PayloadSections[0]
	exit := ev.PayloadSections[1]
	if enter.Kind != "struct" || enter.Direction != "in" || enter.ArgIndex != 0 || enter.UserLen != 16 {
		t.Fatalf("poll enter section = %+v", enter)
	}
	if exit.Kind != "struct" || exit.Direction != "out" || exit.ArgIndex != 0 || exit.UserLen != 16 {
		t.Fatalf("poll exit section = %+v", exit)
	}
	if got := mustDecodeBase64(t, enter.DataBase64); string(got) != "pollfd-enter-000" {
		t.Fatalf("poll enter data = %q", string(got))
	}
	if got := mustDecodeBase64(t, exit.DataBase64); string(got) != "pollfd-exit--000" {
		t.Fatalf("poll exit data = %q", string(got))
	}
}

func TestJSONSyscallEventIncludesPpollTimeoutPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x2000, 1, 0x3000},
		DataLen:       payloadMiscArgOffset + 16,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("pollfd-in"))
	copy(eventRaw.StrArg[payloadMiscArgOffset:], []byte("ppoll-timeout--"))

	scMeta := meta.Syscall{Name: "ppoll"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	pollfds := ev.PayloadSections[0]
	timeout := ev.PayloadSections[1]
	if pollfds.Kind != "struct" || pollfds.Direction != "in" || pollfds.ArgIndex != 0 || pollfds.UserLen != 8 {
		t.Fatalf("ppoll pollfds section = %+v", pollfds)
	}
	if timeout.Kind != "struct" || timeout.Direction != "in" || timeout.ArgIndex != 2 || timeout.UserLen != 16 {
		t.Fatalf("ppoll timeout section = %+v", timeout)
	}
}

func TestJSONSyscallEventIncludesEpollStructPayloadSections(t *testing.T) {
	tests := []struct {
		name      string
		eventRaw  bpfEvent
		wantCount int
	}{
		{
			name: "epoll_ctl",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          [6]uint64{5, 1, 6, 0x3000},
				DataLen:       epollPayloadEventSize,
				ProbeRetEnter: 0,
			},
			wantCount: 1,
		},
		{
			name: "epoll_wait",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{5, 0x2000, 2, 1000},
				Ret:           2,
				DataLen:       payloadExitArgOffset + 24,
				ProbeRetEnter: -1,
				ProbeRetExit:  0,
			},
			wantCount: 1,
		},
		{
			name: "epoll_pwait2",
			eventRaw: bpfEvent{
				EventType:     bpfEventTypeExit,
				Args:          [6]uint64{5, 0x2000, 2, 0x3000, 0, 8},
				Ret:           2,
				DataLen:       payloadExitArgOffset + 24,
				ProbeRetEnter: 0,
				ProbeRetExit:  0,
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := tt.eventRaw
			copy(eventRaw.StrArg[:], bytes.Repeat([]byte{0x11}, epollPayloadEventSize))
			copy(eventRaw.StrArg[payloadMiscArgOffset:], bytes.Repeat([]byte{0x22}, timespecPayloadStructSize))
			copy(eventRaw.StrArg[payloadExitArgOffset:], bytes.Repeat([]byte{0x33}, 24))

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(&eventRaw, scMeta, payloadSectionsForEvent(&eventRaw, scMeta))
			if len(ev.PayloadSections) != tt.wantCount {
				t.Fatalf("PayloadSections = %d, want %d", len(ev.PayloadSections), tt.wantCount)
			}
			for _, section := range ev.PayloadSections {
				if section.Kind != "struct" {
					t.Fatalf("%s section kind = %+v", tt.name, section)
				}
			}
		})
	}
}

func TestJSONSyscallEventIncludesIovecPayloadSection(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
	}{
		{name: "readv", args: [6]uint64{3, 0x3000, 1}},
		{name: "process_madvise", args: [6]uint64{9, 0x3000, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				Pid:           101,
				Tid:           101,
				EventVersion:  2,
				EventType:     bpfEventTypeEnter,
				Args:          tt.args,
				DataLen:       16,
				ProbeRetEnter: 0,
			}
			copy(eventRaw.StrArg[:], []byte("0123456789abcdef"))

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			section := ev.PayloadSections[0]
			if section.Kind != "iovec" || section.Direction != "in" || section.ArgIndex != 1 || section.UserLen != 16 {
				t.Fatalf("%s iovec section metadata = %+v", tt.name, section)
			}
			if got := mustDecodeBase64(t, section.DataBase64); string(got) != "0123456789abcdef" {
				t.Fatalf("%s iovec data = %q, want captured iovec bytes", tt.name, string(got))
			}
		})
	}
}

func TestJSONSyscallEventIncludesMemfdNamePayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		EventVersion:  2,
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x2000, 0},
		DataLen:       uint32(len("memfd-name\x00")),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("memfd-name\x00"))

	scMeta := meta.Syscall{Name: "memfd_create"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "string" || section.Direction != "in" || section.ArgIndex != 0 || section.UserPtr != 0x2000 {
		t.Fatalf("memfd_create section metadata = %+v", section)
	}
	if section.UserLen != uint32(len("memfd-name\x00")) || section.CopiedLen != uint32(len("memfd-name\x00")) {
		t.Fatalf("memfd_create section bounds = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != "memfd-name\x00" {
		t.Fatalf("memfd_create section data = %q, want memfd-name", string(got))
	}
}

func TestJSONSyscallEventClampsMemfdNamePayloadSection(t *testing.T) {
	name := bytes.Repeat([]byte{'a'}, memfdNamePayloadMaxBytes+10)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x2000, 0},
		DataLen:       uint32(len(name)),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], name)

	scMeta := meta.Syscall{Name: "memfd_create"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.UserLen != memfdNamePayloadMaxBytes || section.CopiedLen != memfdNamePayloadMaxBytes {
		t.Fatalf("memfd_create clamped bounds = %+v", section)
	}
}

func TestJSONSyscallEventIncludesProcessVMIovecPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		EventVersion:  2,
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{102, 0x3000, 1, 0x4000, 1, 0},
		DataLen:       payloadMiscArgOffset + 16,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("local-iovec-0000"))
	copy(eventRaw.StrArg[payloadMiscArgOffset:], []byte("remote-iovec-000"))

	scMeta := meta.Syscall{Name: "process_vm_readv"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	local := ev.PayloadSections[0]
	remote := ev.PayloadSections[1]
	if local.Kind != "iovec" || local.ArgIndex != 1 || local.UserPtr != 0x3000 {
		t.Fatalf("local iovec section = %+v", local)
	}
	if remote.Kind != "iovec" || remote.ArgIndex != 3 || remote.UserPtr != 0x4000 {
		t.Fatalf("remote iovec section = %+v", remote)
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
