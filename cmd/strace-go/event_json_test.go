package main

import (
	"bytes"
	"encoding/json"
	"testing"
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
