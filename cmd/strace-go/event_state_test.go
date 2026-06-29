package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

func TestJSONEventsArePairedByTIDState(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "-e", "trace=getpid", "/bin/true"})
	var output bytes.Buffer
	session := &traceSession{
		targetPid: 1234,
		opts:      opts,
		decoder:   event.NewDecoder(),
		fdMap:     make(map[string]string),
		fdOffsets: make(map[string]int64),
		fdFiles:   make(map[string]*os.File),
		outWriter: &output,
	}

	enter := &bpfEvent{
		Pid:          1234,
		Tid:          1234,
		SysId:        39, // getpid
		EventVersion: 2,
		EventType:    bpfEventTypeEnter,
		EventFlags:   bpfEventFlagGenericEnter,
		EnterTime:    100,
	}
	exit := &bpfEvent{
		Pid:          1234,
		Tid:          1234,
		SysId:        39, // getpid
		EventVersion: 2,
		EventType:    bpfEventTypeExit,
		EnterTime:    100,
		Duration:     20,
		Ret:          1234,
	}

	session.handleEvent(enter)
	if len(session.pendingSyscalls) != 1 {
		t.Fatalf("pendingSyscalls after enter = %d, want 1", len(session.pendingSyscalls))
	}
	session.handleEvent(exit)
	if len(session.pendingSyscalls) != 0 {
		t.Fatalf("pendingSyscalls after exit = %d, want 0", len(session.pendingSyscalls))
	}

	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("JSON lines = %d, want enter and exit lines; output=%q", len(lines), output.String())
	}
	var exitEvent struct {
		EventType   string `json:"event_type"`
		PairedEnter bool   `json:"paired_enter"`
	}
	if err := json.Unmarshal(lines[1], &exitEvent); err != nil {
		t.Fatalf("decode exit JSON: %v", err)
	}
	if exitEvent.EventType != "exit" || !exitEvent.PairedEnter {
		t.Fatalf("exit JSON = %+v, want event_type=exit paired_enter=true", exitEvent)
	}
}
