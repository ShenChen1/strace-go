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
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: &output})
	raw := traceEventV2LifecycleSample(t, traceEventV2SampleSpec{
		pid:     101,
		tid:     101,
		flags:   bpfEventFlagTruncated,
		tsNs:    20,
		action:  lifecycleExec,
		args:    [6]uint64{100, 101},
		payload: []byte("/bin/true\x00trailing"),
	})
	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected lifecycle sample")
	}

	writer.WriteLifecycle(envelope.lifecycleView(), &TaskState{
		TID:        101,
		TGID:       101,
		Alive:      true,
		Execed:     true,
		LastAction: "exec",
		LastSeenNS: 20,
	})

	var ev struct {
		Type       string `json:"type"`
		EventFlags uint32 `json:"event_flags"`
		Action     string `json:"action"`
		ActionID   uint32 `json:"action_id"`
		Filename   string `json:"filename"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &ev); err != nil {
		t.Fatalf("decode lifecycle JSON: %v", err)
	}
	if ev.Type != "lifecycle" || ev.EventFlags != bpfEventFlagTruncated ||
		ev.Action != "exec" || ev.ActionID != lifecycleExec || ev.Filename != "/bin/true" {
		t.Fatalf("lifecycle JSON = %+v, want exec filename /bin/true", ev)
	}
}

func TestJSONLifecycleViewIncludesFilenameSnapshot(t *testing.T) {
	var output bytes.Buffer
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: &output})

	writer.WriteLifecycle(lifecycleEventView{
		eventVersion: 2,
		eventType:    bpfEventTypeLifecycle,
		eventFlags:   bpfEventFlagTruncated,
		action:       lifecycleExec,
		pid:          101,
		tid:          101,
		args:         [6]uint64{100, 101},
		enterTime:    20,
		snapshotText: "/bin/true",
	}, &TaskState{
		TID:        101,
		TGID:       101,
		Alive:      true,
		Execed:     true,
		Executable: "/bin/true",
	})

	var ev struct {
		Type           string `json:"type"`
		EventFlags     uint32 `json:"event_flags"`
		Action         string `json:"action"`
		ActionID       uint32 `json:"action_id"`
		Filename       string `json:"filename"`
		TaskExecutable string `json:"task_executable"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &ev); err != nil {
		t.Fatalf("decode lifecycle view JSON: %v", err)
	}
	if ev.Type != "lifecycle" || ev.EventFlags != bpfEventFlagTruncated ||
		ev.Action != "exec" || ev.ActionID != lifecycleExec || ev.Filename != "/bin/true" ||
		ev.TaskExecutable != "/bin/true" {
		t.Fatalf("lifecycle view JSON = %+v, want exec filename /bin/true", ev)
	}
}

func TestJSONStatsEventIncludesRingbufFailures(t *testing.T) {
	ev := newJSONStatsEvent(bpfRuntimeStats{
		RingbufReserveFail:     8,
		RingbufCopyFail:        9,
		PayloadTruncatedEvents: 10,
		PendingUpdateFail:      11,
		OrphanExit:             12,
		PendingMismatch:        13,
		LifecycleMapUpdateFail: 14,
		Available:              true,
	}, 15)
	if ev.Type != "stats" || ev.RingbufReserveFail != 8 || ev.RingbufCopyFail != 9 ||
		ev.PayloadTruncatedEvents != 10 || ev.PendingUpdateFail != 11 || ev.OrphanExit != 12 || ev.PendingMismatch != 13 ||
		ev.LifecycleMapUpdateFail != 14 ||
		ev.PendingStale != 15 || !ev.Available || ev.Error != "" {
		t.Fatalf("stats JSON event = %+v", ev)
	}
}

func TestJSONRawEventViewOverridesRawScalars(t *testing.T) {
	var output bytes.Buffer
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: &output})
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
		stackID:       17,
		probeRetEnter: -1,
		probeRetExit:  0,
	}

	writer.WriteRaw(syscallEventContext{
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
	if ev.StackID != 17 {
		t.Fatalf("raw JSON stack_id = %d, want 17", ev.StackID)
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
