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

	session := &traceSession{
		targetPid: 1234,
		opts:      opts,
		decoder:   decoder,
		fdState:   newFDStateStoreFromMaps(nil, nil, nil),
		outWriter: &output,
	}

	pathPtr := uint64(0x1000)
	session.handleEvent(&bpfEvent{
		Pid:           1234,
		Tid:           1234,
		SysId:         syscallIDByName(t, "openat"),
		EventVersion:  2,
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{rawAtFdcwd, pathPtr, 0},
		Ptr:           pathPtr,
		ProbeRetEnter: -3,
		Ret:           3,
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

	session := &traceSession{
		targetPid: 1234,
		opts:      opts,
		decoder:   decoder,
		fdState:   newFDStateStoreFromMaps(nil, nil, nil),
		outWriter: &output,
	}

	pathPtr := uint64(0x1000)
	howPtr := uint64(0x2000)
	session.handleEvent(&bpfEvent{
		Pid:           1234,
		Tid:           1234,
		SysId:         syscallIDByName(t, "openat2"),
		EventVersion:  2,
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{rawAtFdcwd, pathPtr, howPtr, 24},
		Ptr:           pathPtr,
		ProbeRetEnter: -3,
		Ret:           3,
	})

	if !bytes.Contains(output.Bytes(), []byte(`"syscall":"openat2"`)) {
		t.Fatalf("JSON output missing openat2 event: %s", output.String())
	}
}

func TestTextEventPathDoesNotReadTraceeMemory(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=openat", "/bin/true"})
	var output bytes.Buffer
	decoder := event.NewDecoder()

	session := &traceSession{
		targetPid: 1234,
		opts:      opts,
		decoder:   decoder,
		fdState:   newFDStateStoreFromMaps(nil, nil, nil),
		outWriter: &output,
	}

	pathPtr := uint64(0x1000)
	session.handleEvent(&bpfEvent{
		Pid:           1234,
		Tid:           1234,
		SysId:         syscallIDByName(t, "openat"),
		EventVersion:  2,
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{rawAtFdcwd, pathPtr, 0},
		Ptr:           pathPtr,
		ProbeRetEnter: -3,
		Ret:           3,
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
		name     string
		sc       meta.Syscall
		eventRaw *bpfEvent
	}{
		{
			name: "pipe",
			sc:   meta.Syscall{Name: "pipe"},
			eventRaw: &bpfEvent{
				Pid:  1234,
				Tid:  1234,
				Args: [6]uint64{0x1000},
				Ret:  0,
			},
		},
		{
			name: "socketpair",
			sc:   meta.Syscall{Name: "socketpair"},
			eventRaw: &bpfEvent{
				Pid:  1234,
				Tid:  1234,
				Args: [6]uint64{1, 0, 0, 0x2000},
				Ret:  0,
			},
		},
		{
			name: "bind",
			sc:   meta.Syscall{Name: "bind"},
			eventRaw: &bpfEvent{
				Pid:  1234,
				Tid:  1234,
				Args: [6]uint64{7, 0x3000},
				Ret:  0,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updateFDMapForTest(test.eventRaw, test.sc, "", 101, make(map[string]string))
		})
	}
}
