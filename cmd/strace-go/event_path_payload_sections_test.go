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

func TestJSONSyscallEventIncludesSimplePathPayloadSection(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
		want wantPathJSONPayloadSection
	}{
		{
			name: "chdir",
			args: [6]uint64{0x1000},
			want: wantPathJSONPayloadSection{argIndex: 0, offset: 0, userPtr: 0x1000, data: "/tmp/a"},
		},
		{
			name: "mkdirat",
			args: [6]uint64{^uint64(99), 0x2000},
			want: wantPathJSONPayloadSection{argIndex: 1, offset: 0, userPtr: 0x2000, data: "relative"},
		},
		{
			name: "faccessat2",
			args: [6]uint64{^uint64(99), 0x3000},
			want: wantPathJSONPayloadSection{argIndex: 1, offset: 0, userPtr: 0x3000, data: "check"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				EventType:     bpfEventTypeEnter,
				Args:          tt.args,
				DataLen:       uint32(len(tt.want.data) + 1),
				ProbeRetEnter: 0,
			}
			copy(eventRaw.StrArg[:], []byte(tt.want.data+"\x00"))

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

func TestSimplePathPayloadDoesNotShadowStructuredStat(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x1000, 0x2000},
		Ret:           0,
		DataLen:       statPayloadStructSize + 1024,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}

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
