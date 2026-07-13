package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestWriteJSONDecodedEventUsesSyscallEventView(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}
	ev := syscallEventContext{
		raw: &bpfEvent{
			Pid:          1,
			Tid:          1,
			SysId:        999,
			EventVersion: 2,
			EventType:    bpfEventTypeExit,
			Args:         [6]uint64{1},
			Ret:          123,
		},
		view:           syscallEventView{valid: true, pid: 101, tid: 102, sysID: 39, args: [6]uint64{7}, ret: -2, duration: 55, probeRetEnter: -1},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{},
	}

	session.writeJSONDecodedEvent(ev, handler.Result{ArgParts: []string{"7"}})

	var got jsonSyscallEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatalf("decode syscall JSON: %v", err)
	}
	if got.Pid != 101 || got.Tid != 102 || got.SysID != 39 || got.Args[0] != 7 {
		t.Fatalf("decoded JSON identity = pid:%d tid:%d sys:%d args:%v", got.Pid, got.Tid, got.SysID, got.Args)
	}
	if got.Ret != -2 || !got.Failed || got.Errno != 2 || got.ReturnText != "-1 ENOENT (No such file or directory)" {
		t.Fatalf("decoded JSON return = ret:%d failed:%v errno:%d text:%q", got.Ret, got.Failed, got.Errno, got.ReturnText)
	}
	if got.DurationNS != 55 || got.ProbeRetEnter != -1 {
		t.Fatalf("decoded JSON timing/probe = duration:%d probe:%d", got.DurationNS, got.ProbeRetEnter)
	}
}

func TestWriteJSONDecodedEventUsesHandlerPayloadSections(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}
	ev := syscallEventContext{
		view: syscallEventView{
			valid:     true,
			pid:       101,
			tid:       102,
			sysID:     1,
			eventType: bpfEventTypeExit,
		},
		meta: meta.Syscall{Name: "write"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x1000,
			UserLen:   3,
			CopiedLen: 3,
			Data:      []byte("raw"),
		}},
		handlerContext: &handler.Context{
			PayloadSections: []handler.PayloadSection{{
				Kind:      handler.PayloadKindBytes,
				Direction: handler.PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x2000,
				UserLen:   7,
				CopiedLen: 7,
				Data:      []byte("decoded"),
			}},
		},
	}

	session.writeJSONDecodedEvent(ev, handler.Result{})

	var got jsonSyscallEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatalf("decode syscall JSON: %v", err)
	}
	if len(got.PayloadSections) != 1 {
		t.Fatalf("decoded payload sections = %d, want 1", len(got.PayloadSections))
	}
	section := got.PayloadSections[0]
	if section.ArgIndex != 1 || section.UserPtr != 0x2000 || section.DataBase64 != "ZGVjb2RlZA==" {
		t.Fatalf("decoded payload section = %+v, want handler context section", section)
	}
}

func TestWriteJSONDecodedEventReturnTextUsesHandlerMetadata(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}
	ev := syscallEventContext{
		view: syscallEventView{
			valid: true,
			pid:   101,
			tid:   102,
			sysID: 60,
			ret:   -2,
		},
		handlerContext: &handler.Context{
			ScMeta: meta.Syscall{Name: "getpid"},
		},
	}

	session.writeJSONDecodedEvent(ev, handler.Result{})

	var got jsonSyscallEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatalf("decode syscall JSON: %v", err)
	}
	if got.Syscall != "getpid" {
		t.Fatalf("syscall = %q, want handler metadata syscall", got.Syscall)
	}
	if got.ReturnText != "-1 ENOENT (No such file or directory)" {
		t.Fatalf("return_text = %q, want errno text from handler metadata", got.ReturnText)
	}
}

func TestWriteJSONDecodedEventOmitsPayloadWithoutHandlerContext(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}
	ev := syscallEventContext{
		view: syscallEventView{
			valid:     true,
			pid:       101,
			tid:       102,
			sysID:     1,
			eventType: bpfEventTypeExit,
		},
		meta: meta.Syscall{Name: "write"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  2,
			Data:      []byte("raw"),
		}},
	}

	session.writeJSONDecodedEvent(ev, handler.Result{})

	var got jsonSyscallEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatalf("decode syscall JSON: %v", err)
	}
	if len(got.PayloadSections) != 0 {
		t.Fatalf("decoded payload sections = %+v, want none without handler context", got.PayloadSections)
	}
}
