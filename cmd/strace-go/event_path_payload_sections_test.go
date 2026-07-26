package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

type wantPathJSONPayloadSection struct {
	argIndex int
	userPtr  uint64
	data     string
}

func TestJSONSyscallEventIncludesSimplePathPayloadSection(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
		want wantPathJSONPayloadSection
	}{
		{
			name: "chdir",
			args: [6]uint64{0x1000},
			want: wantPathJSONPayloadSection{argIndex: 0, userPtr: 0x1000, data: "/tmp/a"},
		},
		{
			name: "mkdirat",
			args: [6]uint64{^uint64(99), 0x2000},
			want: wantPathJSONPayloadSection{argIndex: 1, userPtr: 0x2000, data: "relative"},
		},
		{
			name: "faccessat2",
			args: [6]uint64{^uint64(99), 0x3000},
			want: wantPathJSONPayloadSection{argIndex: 1, userPtr: 0x3000, data: "check"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := pathJSONTLVPayload(t, []wantPathJSONPayloadSection{tt.want})
			eventRaw := &bpfEvent{
				EventType:     bpfEventTypeEnter,
				EventFlags:    bpfEventFlagPayloadTLV,
				Args:          tt.args,
				DataLen:       uint32(len(payload)),
				ProbeRetEnter: 0,
			}
			copy(eventRaw.StrArg[:], payload)

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			assertPathJSONPayloadSection(t, ev.PayloadSections[0], tt.want)
		})
	}
}

func TestJSONSyscallEventDoesNotUseFixedOpenatPathPayload(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{^uint64(99), 0x2000},
		DataLen:       uint32(len("legacy") + 1),
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[:], []byte("legacy\x00"))

	scMeta := meta.Syscall{Name: "openat"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 0 {
		t.Fatalf("PayloadSections = %d, want no fixed openat path fallback", len(ev.PayloadSections))
	}
}

func TestJSONSyscallEventIncludesStatStructPayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x42}, statPayloadStructSize)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: uint32(len(wantData)),
		data:    wantData,
	})
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		EventFlags:    bpfEventFlagPayloadTLV,
		Args:          [6]uint64{0x1000, 0x2000},
		Ret:           0,
		DataLen:       uint32(len(payload)),
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "stat"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 || ev.PayloadSections[0].Kind != "struct" || ev.PayloadSections[0].ArgIndex != 1 {
		t.Fatalf("stat PayloadSections = %+v, want only stat struct section", ev.PayloadSections)
	}
}

func TestJSONSyscallEventIncludesDualPathPayloadSections(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
		want []wantPathJSONPayloadSection
	}{
		{
			name: "rename",
			args: [6]uint64{0x1000, 0x2000},
			want: []wantPathJSONPayloadSection{
				{argIndex: 0, userPtr: 0x1000, data: "old"},
				{argIndex: 1, userPtr: 0x2000, data: "new"},
			},
		},
		{
			name: "symlinkat",
			args: [6]uint64{0x3000, ^uint64(99), 0x4000},
			want: []wantPathJSONPayloadSection{
				{argIndex: 0, userPtr: 0x3000, data: "target"},
				{argIndex: 2, userPtr: 0x4000, data: "link"},
			},
		},
		{
			name: "linkat",
			args: [6]uint64{^uint64(99), 0x5000, ^uint64(100), 0x6000},
			want: []wantPathJSONPayloadSection{
				{argIndex: 1, userPtr: 0x5000, data: "old-at"},
				{argIndex: 3, userPtr: 0x6000, data: "new-at"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := pathJSONTLVPayload(t, tt.want)
			eventRaw := &bpfEvent{
				EventType:     bpfEventTypeEnter,
				EventFlags:    bpfEventFlagPayloadTLV,
				Args:          tt.args,
				DataLen:       uint32(len(payload)),
				ProbeRetEnter: 0,
			}
			copy(eventRaw.StrArg[:], payload)

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != len(tt.want) {
				t.Fatalf("PayloadSections = %d, want %d", len(ev.PayloadSections), len(tt.want))
			}
			for i := range tt.want {
				assertPathJSONPayloadSection(t, ev.PayloadSections[i], tt.want[i])
			}
		})
	}
}

func pathJSONTLVPayload(t *testing.T, wants []wantPathJSONPayloadSection) []byte {
	t.Helper()
	var payload []byte
	for _, want := range wants {
		data := []byte(want.data + "\x00")
		payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindString,
			arg:     uint16(want.argIndex),
			userPtr: want.userPtr,
			userLen: uint32(len(data)),
			data:    data,
		})...)
	}
	return payload
}

func assertPathJSONPayloadSection(
	t *testing.T,
	got jsonPayloadSection,
	want wantPathJSONPayloadSection,
) {
	t.Helper()
	if got.Kind != "string" || got.Direction != "in" || got.ArgIndex != want.argIndex {
		t.Fatalf("path section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr {
		t.Fatalf("path section bounds = %+v, want %+v", got, want)
	}
	wantData := want.data + "\x00"
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("path section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); string(data) != wantData {
		t.Fatalf("path section data = %q, want %q", string(data), wantData)
	}
}
