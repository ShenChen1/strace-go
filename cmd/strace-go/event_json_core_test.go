package main

import (
	"bytes"
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

	session.writeJSONLifecycleEventView(newTraceStateEventViewFromBPF(eventRaw), &TaskState{
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

func TestJSONLifecycleViewIncludesFilenameSnapshot(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}

	session.writeJSONLifecycleEventView(traceStateEventView{
		eventVersion: 2,
		eventType:    bpfEventTypeLifecycle,
		eventFlags:   lifecycleExec,
		pid:          101,
		tid:          101,
		args:         [6]uint64{100, 101},
		enterTime:    20,
		snapshotText: "/bin/true",
	}, &TaskState{
		TID:    101,
		TGID:   101,
		Alive:  true,
		Execed: true,
	})

	var ev struct {
		Type     string `json:"type"`
		Action   string `json:"action"`
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &ev); err != nil {
		t.Fatalf("decode lifecycle view JSON: %v", err)
	}
	if ev.Type != "lifecycle" || ev.Action != "exec" || ev.Filename != "/bin/true" {
		t.Fatalf("lifecycle view JSON = %+v, want exec filename /bin/true", ev)
	}
}

func TestJSONStatsEventIncludesRingbufFailures(t *testing.T) {
	ev := newJSONStatsEvent(bpfRuntimeStats{
		RingbufReserveFail: 8,
		RingbufCopyFail:    9,
		Available:          true,
	})
	if ev.Type != "stats" || ev.RingbufReserveFail != 8 || ev.RingbufCopyFail != 9 || !ev.Available || ev.Error != "" {
		t.Fatalf("stats JSON event = %+v", ev)
	}
}

func TestJSONRawEventViewOverridesRawScalars(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}
	raw := &bpfEvent{
		Pid:       1,
		Tid:       1,
		SysId:     39,
		EventType: bpfEventTypeExit,
		Args:      [6]uint64{3},
		Ret:       0,
	}
	view := syscallEventView{
		valid:         true,
		eventVersion:  2,
		pid:           200,
		tid:           201,
		sysID:         60,
		eventType:     bpfEventTypeExit,
		eventFlags:    bpfEventFlagGenericEnter,
		args:          [6]uint64{5},
		ret:           -2,
		duration:      55,
		enterTime:     77,
		ptr:           0x1234,
		probeRetEnter: -1,
		probeRetExit:  0,
	}

	session.writeJSONRawEvent(syscallEventContext{
		raw:  raw,
		view: view,
		meta: meta.Syscall{Name: "exit"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0xfeed,
			UserLen:   3,
			CopiedLen: 3,
			Data:      []byte("hit"),
		}},
	})

	var ev jsonSyscallEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &ev); err != nil {
		t.Fatalf("decode raw JSON: %v", err)
	}
	if ev.Pid != 200 || ev.Tid != 201 || ev.SysID != 60 || ev.Args[0] != 5 || ev.Ret != -2 {
		t.Fatalf("raw JSON scalars = %+v, want view pid/tid/sysid/args/ret", ev)
	}
	if ev.EventVersion != 2 || ev.EventFlags != bpfEventFlagGenericEnter || ev.DurationNS != 55 || ev.EnterTimeNS != 77 {
		t.Fatalf("raw JSON timing/header = %+v, want view header/timing", ev)
	}
	if !ev.Failed || ev.Errno != 2 {
		t.Fatalf("raw JSON failure/payload fields = %+v, want view-derived fields", ev)
	}
	if len(ev.PayloadSections) != 1 || ev.PayloadSections[0].ArgIndex != 2 || ev.PayloadSections[0].DataBase64 != "aGl0" {
		t.Fatalf("raw JSON payload sections = %+v, want cached payload section", ev.PayloadSections)
	}
	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &rawFields); err != nil {
		t.Fatalf("decode raw JSON fields: %v", err)
	}
	if _, ok := rawFields["data_len"]; ok {
		t.Fatalf("raw JSON leaked fixed-window data_len field: %s", bytes.TrimSpace(output.Bytes()))
	}
	if _, ok := rawFields["ptr"]; ok {
		t.Fatalf("raw JSON leaked raw pointer field: %s", bytes.TrimSpace(output.Bytes()))
	}
}
