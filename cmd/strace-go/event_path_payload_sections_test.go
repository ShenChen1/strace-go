package main

import (
	"testing"

	"strace-go/pkg/meta"
)

type wantPathJSONPayloadSection struct {
	argIndex int
	offset   uint32
	userPtr  uint64
	data     string
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
				{argIndex: 0, offset: 0, userPtr: 0x1000, data: "old"},
				{argIndex: 1, offset: 512, userPtr: 0x2000, data: "new"},
			},
		},
		{
			name: "symlinkat",
			args: [6]uint64{0x3000, ^uint64(99), 0x4000},
			want: []wantPathJSONPayloadSection{
				{argIndex: 0, offset: 0, userPtr: 0x3000, data: "target"},
				{argIndex: 2, offset: 512, userPtr: 0x4000, data: "link"},
			},
		},
		{
			name: "linkat",
			args: [6]uint64{^uint64(99), 0x5000, ^uint64(100), 0x6000},
			want: []wantPathJSONPayloadSection{
				{argIndex: 1, offset: 0, userPtr: 0x5000, data: "old-at"},
				{argIndex: 3, offset: 512, userPtr: 0x6000, data: "new-at"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          tt.args,
				DataLen:       pathPayloadSecondaryOffset + pathPayloadMaxBytes,
				ProbeRetEnter: 0,
			}
			copy(eventRaw.StrArg[:], []byte(tt.want[0].data+"\x00"))
			copy(eventRaw.StrArg[pathPayloadSecondaryOffset:], []byte(tt.want[1].data+"\x00"))

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

func assertPathJSONPayloadSection(
	t *testing.T,
	got jsonPayloadSection,
	want wantPathJSONPayloadSection,
) {
	t.Helper()
	if got.Kind != "string" || got.Direction != "in" || got.ArgIndex != want.argIndex {
		t.Fatalf("path section metadata = %+v, want %+v", got, want)
	}
	if got.Offset != want.offset || got.UserPtr != want.userPtr {
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
