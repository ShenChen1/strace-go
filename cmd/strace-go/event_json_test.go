package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONLifecycleExecIncludesFilenameSnapshot(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}
	eventRaw := &bpfEvent{
		Pid:          101,
		Tid:          101,
		EventVersion: 2,
		EventType:    bpfEventTypeLifecycle,
		EventFlags:   lifecycleExec,
		EnterTime:    20,
		Args:         [6]uint64{100, 101},
		DataLen:      uint32(len("/bin/true") + 1),
	}
	copy(eventRaw.StrArg[:], []byte("/bin/true\x00trailing"))

	session.writeJSONLifecycleEvent(eventRaw, &TaskState{
		TID:        101,
		TGID:       101,
		Alive:      true,
		Execed:     true,
		LastAction: "exec",
		LastSeenNS: 20,
	})

	var ev struct {
		Type     string `json:"type"`
		Action   string `json:"action"`
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &ev); err != nil {
		t.Fatalf("decode lifecycle JSON: %v", err)
	}
	if ev.Type != "lifecycle" || ev.Action != "exec" || ev.Filename != "/bin/true" {
		t.Fatalf("lifecycle JSON = %+v, want exec filename /bin/true", ev)
	}
}

func TestJSONSyscallEventIncludesWritePayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         1,
		EventVersion:  2,
		EventType:     bpfEventTypeEnter,
		EventFlags:    bpfEventFlagGenericEnter,
		Args:          [6]uint64{1, 0x2000, 5},
		DataLen:       5,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("hello"))

	scMeta := meta.Syscall{Name: "write"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != 1 || section.Offset != 0 {
		t.Fatalf("write section metadata = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != "hello" {
		t.Fatalf("write section data = %q, want hello", string(got))
	}
}

func TestJSONSyscallEventIncludesReadPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		SysId:         0,
		EventVersion:  2,
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x3000, 16},
		Ret:           4,
		DataLen:       handler.BpfExitArgOffset + 4,
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[handler.BpfExitArgOffset:], []byte("data"))

	scMeta := meta.Syscall{Name: "read"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "bytes" || section.Direction != "out" || section.ArgIndex != 1 || section.Offset != handler.BpfExitArgOffset {
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
				DataLen:       handler.BpfExitArgOffset + 6,
				ProbeRetEnter: -1,
				ProbeRetExit:  0,
			}
			copy(eventRaw.StrArg[handler.BpfExitArgOffset:], []byte("target"))

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

func TestJSONSyscallEventIncludesIovecPayloadSection(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		EventVersion:  2,
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{3, 0x3000, 1},
		DataLen:       16,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("0123456789abcdef"))

	scMeta := meta.Syscall{Name: "readv"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "iovec" || section.Direction != "in" || section.ArgIndex != 1 || section.UserLen != 16 {
		t.Fatalf("readv iovec section metadata = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != "0123456789abcdef" {
		t.Fatalf("readv iovec data = %q, want captured iovec bytes", string(got))
	}
}

func TestJSONSyscallEventIncludesProcessVMIovecPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		EventVersion:  2,
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{102, 0x3000, 1, 0x4000, 1, 0},
		DataLen:       handler.BpfMiscArgOffset + 16,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("local-iovec-0000"))
	copy(eventRaw.StrArg[handler.BpfMiscArgOffset:], []byte("remote-iovec-000"))

	scMeta := meta.Syscall{Name: "process_vm_readv"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	local := ev.PayloadSections[0]
	remote := ev.PayloadSections[1]
	if local.Kind != "iovec" || local.ArgIndex != 1 || local.Offset != 0 || local.UserPtr != 0x3000 {
		t.Fatalf("local iovec section = %+v", local)
	}
	if remote.Kind != "iovec" || remote.ArgIndex != 3 || remote.Offset != handler.BpfMiscArgOffset || remote.UserPtr != 0x4000 {
		t.Fatalf("remote iovec section = %+v", remote)
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
