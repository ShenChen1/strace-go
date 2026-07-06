package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesAddKeyPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000, 3},
		DataLen:       keyDataPayloadOffset + 3,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[keyTypePayloadOffset:], []byte("user\x00"))
	copy(eventRaw.StrArg[keyDescriptionPayloadOffset:], []byte("desc\x00"))
	copy(eventRaw.StrArg[keyDataPayloadOffset:], []byte("abc"))

	sections := keyJSONPayloadSections(t, eventRaw, "add_key")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertKeyJSONSection(t, sections[0], "string", 0, keyTypePayloadOffset, 0x1000, []byte("user\x00"))
	assertKeyJSONSection(t, sections[1], "string", 1, keyDescriptionPayloadOffset, 0x2000, []byte("desc\x00"))
	assertKeyJSONSection(t, sections[2], "bytes", 2, keyDataPayloadOffset, 0x3000, []byte("abc"))
}

func TestJSONSyscallEventIncludesRequestKeyPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x1000, 0x2000, 0x3000},
		DataLen:       keyDataPayloadOffset + keyDataPayloadMaxBytes,
		ProbeRetEnter: 0,
	}
	copy(eventRaw.StrArg[keyTypePayloadOffset:], []byte("user\x00"))
	copy(eventRaw.StrArg[keyDescriptionPayloadOffset:], []byte("desc\x00"))
	copy(eventRaw.StrArg[keyDataPayloadOffset:], []byte("info\x00"))

	sections := keyJSONPayloadSections(t, eventRaw, "request_key")
	if len(sections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(sections))
	}
	assertKeyJSONSection(t, sections[0], "string", 0, keyTypePayloadOffset, 0x1000, []byte("user\x00"))
	assertKeyJSONSection(t, sections[1], "string", 1, keyDescriptionPayloadOffset, 0x2000, []byte("desc\x00"))
	assertKeyJSONSection(t, sections[2], "string", 2, keyDataPayloadOffset, 0x3000, []byte("info\x00"))
}

func TestPayloadSectionsForPayloadEventUsesSourceAwareKeyRules(t *testing.T) {
	tests := []struct {
		name      string
		args      [6]uint64
		data      []byte
		wantKinds []handler.PayloadKind
		wantData  [][]byte
	}{
		{
			name: "add_key",
			args: [6]uint64{0x1000, 0x2000, 0x3000, 3},
			data: keySourcePayloadData([]byte("user\x00"), []byte("desc\x00"), []byte("abc")),
			wantKinds: []handler.PayloadKind{
				handler.PayloadKindString,
				handler.PayloadKindString,
				handler.PayloadKindBytes,
			},
			wantData: [][]byte{[]byte("user\x00"), []byte("desc\x00"), []byte("abc")},
		},
		{
			name: "request_key",
			args: [6]uint64{0x1000, 0x2000, 0x3000},
			data: keySourcePayloadData([]byte("user\x00"), []byte("desc\x00"), []byte("info\x00")),
			wantKinds: []handler.PayloadKind{
				handler.PayloadKindString,
				handler.PayloadKindString,
				handler.PayloadKindString,
			},
			wantData: [][]byte{[]byte("user\x00"), []byte("desc\x00"), []byte("info\x00")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := &bpfEvent{EventType: bpfEventTypeEnter, Args: tt.args, ProbeRetEnter: 0}
			event := payloadEvent{
				raw: raw,
				source: staticPayloadSource{
					args: tt.args,
					data: tt.data,
				},
			}

			sections := payloadSectionsForPayloadEvent(event, meta.Syscall{Name: tt.name})

			if len(sections) != len(tt.wantData) {
				t.Fatalf("sections = %d, want %d", len(sections), len(tt.wantData))
			}
			for i := range sections {
				if sections[i].Kind != tt.wantKinds[i] || sections[i].Direction != handler.PayloadDirectionIn {
					t.Fatalf("section[%d] metadata = %+v", i, sections[i])
				}
				if !bytes.Equal(sections[i].Data, tt.wantData[i]) {
					t.Fatalf("section[%d] data = %v, want %v", i, sections[i].Data, tt.wantData[i])
				}
			}
		})
	}
}

func keySourcePayloadData(typeData []byte, descData []byte, payloadData []byte) []byte {
	data := make([]byte, keyDataPayloadOffset+keyDataPayloadMaxBytes)
	copy(data[keyTypePayloadOffset:], typeData)
	copy(data[keyDescriptionPayloadOffset:], descData)
	copy(data[keyDataPayloadOffset:], payloadData)
	return data
}

func keyJSONPayloadSections(t *testing.T, eventRaw *bpfEvent, name string) []jsonPayloadSection {
	t.Helper()
	scMeta := meta.Syscall{Name: name}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	return ev.PayloadSections
}

func assertKeyJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	kind string,
	argIndex int,
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != kind || got.Direction != "in" || got.ArgIndex != argIndex {
		t.Fatalf("key section metadata = %+v", got)
	}
	if got.Offset != uint32(offset) || got.UserPtr != userPtr {
		t.Fatalf("key section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("key section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("key section data = %v, want %v", data, wantData)
	}
}
