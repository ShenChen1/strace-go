package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
)

func TestAppendJSONSyscallEventMatchesStandardEncoding(t *testing.T) {
	event := jsonSyscallEvent{
		Type:         "syscall",
		EventVersion: 2,
		EventType:    "ex\x01it",
		EventTypeID:  2,
		EventFlags:   bpfEventFlagPayloadTLV | bpfEventFlagTruncated,
		Pid:          101,
		Tid:          102,
		SysID:        257,
		Syscall:      string([]byte{'o', '<', '>', '&', '\xff'}),
		Args:         [6]uint64{1, 2, 3, 4, 5, 6},
		ArgText:      []string{"quoted\"", "line\n", "separator\u2028"},
		Ret:          -2,
		ReturnText:   "-1 ENOENT (No such file or directory)",
		Failed:       true,
		Errno:        2,
		DurationNS:   55,
		EnterTimeNS:  77,
		StackID:      -1,
		PayloadSections: []jsonPayloadSection{{
			Kind:       "bytes",
			Direction:  "in",
			ArgIndex:   1,
			UserPtr:    0x2000,
			UserLen:    7,
			CopiedLen:  3,
			ProbeRet:   -3,
			DataBase64: "/w==",
		}},
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
		PairedEnter:   true,
	}

	want, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal standard event: %v", err)
	}
	want = append(want, '\n')
	got := appendJSONSyscallEvent(nil, &event)
	if !bytes.Equal(got, want) {
		t.Fatalf("append JSON differs from standard encoding:\n got: %s\nwant: %s", got, want)
	}
}

func TestAppendJSONSyscallEventOmitsZeroOptionalFields(t *testing.T) {
	event := jsonSyscallEvent{
		Type:          "syscall",
		EventType:     "enter",
		Pid:           1,
		Tid:           1,
		SysID:         39,
		Syscall:       "getpid",
		Failed:        false,
		Args:          [6]uint64{},
		ProbeRetEnter: 0,
	}

	want, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal standard event: %v", err)
	}
	want = append(want, '\n')
	got := appendJSONSyscallEvent(nil, &event)
	if !bytes.Equal(got, want) {
		t.Fatalf("append JSON differs for omitted fields:\n got: %s\nwant: %s", got, want)
	}
}

func TestAppendJSONSyscallReturnPreservesFDPath(t *testing.T) {
	ctx := &handler.Context{
		Pid:  101,
		Args: [6]uint64{3},
		Opts: &cli.Options{ShowPaths: true, ShowPathsMode: 1},
		FDStateView: newFDStateStore(map[string]string{
			"101:3": "/dev/null",
		}),
	}

	got := appendJSONSyscallReturn(nil, "signalfd", 3, handler.Result{}, ctx)
	if string(got) != `"3\u003c/dev/null\u003e"` {
		t.Fatalf("FD return text = %q, want %q", got, `"3\u003c/dev/null\u003e"`)
	}
}

func TestAppendJSONPayloadSectionRawDataMatchesEagerBase64(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xfe, 0xff, 0x02}
	value := jsonPayloadSection{
		Kind:      "bytes",
		Direction: "out",
		ArgIndex:  1,
		UserPtr:   0x3000,
		UserLen:   uint32(len(raw)),
		CopiedLen: uint32(len(raw)),
		ProbeRet:  0,
		rawData:   raw,
	}
	eager := value
	eager.rawData = nil
	eager.DataBase64 = base64.StdEncoding.EncodeToString(raw)

	want, err := json.Marshal(eager)
	if err != nil {
		t.Fatalf("marshal eager payload: %v", err)
	}
	got := appendJSONPayloadSection(nil, value)
	if !bytes.Equal(got, want) {
		t.Fatalf("raw payload JSON differs from eager encoding:\n got: %s\nwant: %s", got, want)
	}
}
