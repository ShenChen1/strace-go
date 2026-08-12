package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

const rawAtFdcwd = ^uint64(99)

func TestJSONEventPathDoesNotReadTraceeMemory(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "-e", "trace=openat", "/bin/true"})
	var output bytes.Buffer
	decoder := event.NewDecoder()

	session := newTestTraceSessionWithOptions(opts, traceSessionDeps{
		TargetPID: 1234,
		Decoder:   decoder,
		FDState:   newFDStateStoreFromMaps(nil, nil),
		OutWriter: &output,
		State:     newTraceState(),
	})

	pathPtr := uint64(0x1000)
	session.handleEnvelope(traceEventEnvelope{
		valid:         true,
		pid:           1234,
		tid:           1234,
		sysID:         syscallIDByName(t, "openat"),
		eventVersion:  2,
		eventType:     bpfEventTypeExit,
		args:          [6]uint64{rawAtFdcwd, pathPtr, 0},
		ptr:           pathPtr,
		probeRetEnter: -3,
		ret:           3,
	})

	if bytes.Contains(output.Bytes(), []byte(`"raw_string"`)) {
		t.Fatalf("JSON output still exposes raw_string: %s", output.String())
	}
	if !bytes.Contains(output.Bytes(), []byte(`"0x1000"`)) {
		t.Fatalf("JSON output did not preserve pointer fallback in arg_text: %s", output.String())
	}
}

func TestJSONHandlerContextDoesNotReadTraceeMemory(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "-e", "trace=openat2", "/bin/true"})
	var output bytes.Buffer
	decoder := event.NewDecoder()

	session := newTestTraceSessionWithOptions(opts, traceSessionDeps{
		TargetPID: 1234,
		Decoder:   decoder,
		FDState:   newFDStateStoreFromMaps(nil, nil),
		OutWriter: &output,
		State:     newTraceState(),
	})

	pathPtr := uint64(0x1000)
	howPtr := uint64(0x2000)
	session.handleEnvelope(traceEventEnvelope{
		valid:         true,
		pid:           1234,
		tid:           1234,
		sysID:         syscallIDByName(t, "openat2"),
		eventVersion:  2,
		eventType:     bpfEventTypeExit,
		args:          [6]uint64{rawAtFdcwd, pathPtr, howPtr, 24},
		ptr:           pathPtr,
		probeRetEnter: -3,
		ret:           3,
	})

	if !bytes.Contains(output.Bytes(), []byte(`"syscall":"openat2"`)) {
		t.Fatalf("JSON output missing openat2 event: %s", output.String())
	}
}

func TestTextEventPathDoesNotReadTraceeMemory(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"})
	var output bytes.Buffer
	decoder := event.NewDecoder()

	session := newTestTraceSessionWithOptions(opts, traceSessionDeps{
		TargetPID: 1234,
		Decoder:   decoder,
		FDState:   newFDStateStoreFromMaps(nil, nil),
		OutWriter: &output,
		State:     newTraceState(),
	})

	pathPtr := uint64(0x1000)
	session.handleEnvelope(traceEventEnvelope{
		valid:         true,
		pid:           1234,
		tid:           1234,
		sysID:         syscallIDByName(t, "openat"),
		eventVersion:  2,
		eventType:     bpfEventTypeExit,
		args:          [6]uint64{rawAtFdcwd, pathPtr, 0},
		ptr:           pathPtr,
		probeRetEnter: -3,
		ret:           3,
	})

	if bytes.Contains(output.Bytes(), []byte("from-memory")) {
		t.Fatalf("text output used tracee memory fallback: %s", output.String())
	}
	if !bytes.Contains(output.Bytes(), []byte("0x1000")) {
		t.Fatalf("text output did not preserve pointer fallback: %s", output.String())
	}
}

func TestUpdateFDMapDoesNotReadTraceeMemoryWhenFallbackDisabled(t *testing.T) {
	tests := []struct {
		name string
		sc   meta.Syscall
		view syscallEventView
	}{
		{
			name: "pipe",
			sc:   meta.Syscall{Name: "pipe"},
			view: syscallEventView{valid: true, pid: 1234, tid: 1234, args: [6]uint64{0x1000}, ret: 0},
		},
		{
			name: "socketpair",
			sc:   meta.Syscall{Name: "socketpair"},
			view: syscallEventView{valid: true, pid: 1234, tid: 1234, args: [6]uint64{1, 0, 0, 0x2000}, ret: 0},
		},
		{
			name: "bind",
			sc:   meta.Syscall{Name: "bind"},
			view: syscallEventView{valid: true, pid: 1234, tid: 1234, args: [6]uint64{7, 0x3000}, ret: 0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updateFDMapForTest(test.view, test.sc, nil, "", 101, make(map[string]string))
		})
	}
}
