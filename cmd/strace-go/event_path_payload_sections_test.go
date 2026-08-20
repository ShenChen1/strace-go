package main

import (
	"bytes"
	"testing"
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
			payload := payloadTLVBytesForTest(t, pathJSONTLVSections([]wantPathJSONPayloadSection{tt.want})...)
			ev := newJSONSyscallEventFromTLVForTest(t, tt.name, bpfEventTypeEnter, tt.args, 0, payload)
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			assertPathJSONPayloadSection(t, ev.PayloadSections[0], tt.want)
		})
	}
}

func TestPayloadSectionsForRawPayloadEventDoesNotUseFixedOpenatPathPayload(t *testing.T) {
	raw := rawPayloadEvent{
		valid:         true,
		eventType:     bpfEventTypeEnter,
		args:          [6]uint64{^uint64(99), 0x2000},
		probeRetEnter: 0,
		data:          []byte("legacy\x00"),
	}

	sections := payloadSectionsForRawPayloadEvent(raw)
	if len(sections) != 0 {
		t.Fatalf("PayloadSections = %d, want no fixed openat path fallback", len(sections))
	}
}

func TestJSONSyscallEventIncludesStatStructPayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x42}, statPayloadStructSize)
	args := [6]uint64{0x1000, 0x2000}
	payload := payloadTLVBytesForTest(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: uint32(len(wantData)),
		data:    wantData,
	})

	ev := newJSONSyscallEventFromTLVForTest(t, "stat", bpfEventTypeExit, args, 0, payload)
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
			payload := payloadTLVBytesForTest(t, pathJSONTLVSections(tt.want)...)
			ev := newJSONSyscallEventFromTLVForTest(t, tt.name, bpfEventTypeEnter, tt.args, 0, payload)
			if len(ev.PayloadSections) != len(tt.want) {
				t.Fatalf("PayloadSections = %d, want %d", len(ev.PayloadSections), len(tt.want))
			}
			for i := range tt.want {
				assertPathJSONPayloadSection(t, ev.PayloadSections[i], tt.want[i])
			}
		})
	}
}

func pathJSONTLVSections(wants []wantPathJSONPayloadSection) []payloadTLVTestSection {
	sections := make([]payloadTLVTestSection, 0, len(wants))
	for _, want := range wants {
		data := []byte(want.data + "\x00")
		sections = append(sections, payloadTLVTestSection{
			kind:    payloadTLVKindString,
			arg:     uint16(want.argIndex),
			userPtr: want.userPtr,
			userLen: uint32(len(data)),
			data:    data,
		})
	}
	return sections
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
