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

	ev := newJSONSyscallEvent(eventRaw, meta.Syscall{Name: "write"})
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

	ev := newJSONSyscallEvent(eventRaw, meta.Syscall{Name: "read"})
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

func mustDecodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return data
}
