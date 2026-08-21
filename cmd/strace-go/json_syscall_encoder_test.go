package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONLineBuilderFieldTokenBoundaries(t *testing.T) {
	var builder jsonLineBuilder
	builder.beginObject()
	builder.beginFieldToken(`"type":`)
	builder.data = append(builder.data, `"syscall"`...)
	builder.beginFieldToken(`"pid":`)
	builder.data = append(builder.data, '7')
	if got := string(builder.endLine()); got != "{\"type\":\"syscall\",\"pid\":7}\n" {
		t.Fatalf("token fields = %q, want %q", got, "{\"type\":\"syscall\",\"pid\":7}\n")
	}

	var empty jsonLineBuilder
	empty.beginObject()
	if got := string(empty.endLine()); got != "{}\n" {
		t.Fatalf("empty token object = %q, want %q", got, "{}\n")
	}
}

func TestJSONLineBuilderTrustedStringField(t *testing.T) {
	var builder jsonLineBuilder
	builder.beginObject()
	builder.trustedStringField(jsonFieldType, "syscall")
	if got := string(builder.endLine()); got != `{"type":"syscall"}`+"\n" {
		t.Fatalf("trusted string field = %q, want %q", got, `{"type":"syscall"}`+"\n")
	}
}

func TestJSONLineBuilderZeroUint64ArrayField(t *testing.T) {
	var builder jsonLineBuilder
	builder.beginObject()
	builder.zeroUint64ArrayField(jsonFieldArgs)
	if got := string(builder.endLine()); got != `{"args":[0,0,0,0,0,0]}`+"\n" {
		t.Fatalf("zero args field = %q, want %q", got, `{"args":[0,0,0,0,0,0]}`+"\n")
	}
}

func TestAppendJSONDecodedSyscallEventMatchesMaterializedEncoding(t *testing.T) {
	event := syscallEventContext{
		view: syscallEventView{
			valid:         true,
			eventVersion:  traceEventV2Version,
			pid:           101,
			tid:           102,
			sysID:         1,
			eventType:     bpfEventTypeExit,
			eventFlags:    bpfEventFlagPayloadTLV,
			args:          [6]uint64{1, 0x2000, 7},
			ret:           -2,
			duration:      55,
			enterTime:     77,
			stackID:       -1,
			probeRetEnter: -1,
			probeRetExit:  0,
		},
		meta:         meta.Syscall{Name: "write"},
		pendingEnter: &pendingSyscallSnapshot{genericEnterRaw: true},
		handlerContext: &handler.Context{PayloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x2000,
			UserLen:   7,
			CopiedLen: 7,
			Data:      []byte("payload"),
		}}},
	}
	result := handler.Result{ArgParts: []string{"1", "\"payload\""}}

	got := appendJSONDecodedSyscallEvent(nil, event, result)
	materialized := event.newJSONDecodedSyscallEvent(result)
	want := appendJSONSyscallEvent(nil, &materialized)
	if !bytes.Equal(got, want) {
		t.Fatalf("direct decoded JSON differs from materialized encoding:\n got: %s\nwant: %s", got, want)
	}
}

func TestAppendJSONRawSyscallEventMatchesMaterializedEncoding(t *testing.T) {
	event := syscallEventContext{
		view: syscallEventView{
			valid:         true,
			eventVersion:  traceEventV2Version,
			pid:           101,
			tid:           102,
			sysID:         39,
			eventType:     bpfEventTypeEnter,
			eventFlags:    bpfEventFlagGenericEnter,
			args:          [6]uint64{7},
			enterTime:     77,
			probeRetEnter: -1,
		},
		meta: meta.Syscall{Name: "getpid"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x2000,
			UserLen:   3,
			CopiedLen: 3,
			Data:      []byte("raw"),
		}},
	}

	got := appendJSONRawSyscallEvent(nil, event)
	materialized := event.newJSONRawSyscallEvent()
	want := appendJSONSyscallEvent(nil, &materialized)
	if !bytes.Equal(got, want) {
		t.Fatalf("direct raw JSON differs from materialized encoding:\n got: %s\nwant: %s", got, want)
	}
}

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
