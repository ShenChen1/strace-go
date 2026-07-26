package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type wantSelectJSONPayloadSection struct {
	kind      string
	direction string
	argIndex  int
	userPtr   uint64
	userLen   uint32
	data      []byte
}

func TestJSONSyscallEventIncludesSelectPayloadSections(t *testing.T) {
	want := []wantSelectJSONPayloadSection{
		{"bytes", "in", 1, 0x1000, 1, selectJSONFdSetData(3)[:1]},
		{"bytes", "in", 2, 0x2000, 1, selectJSONFdSetData(4)[:1]},
		{"struct", "in", 4, 0x3000, 16, selectJSONTimeval(9, 10)},
		{"bytes", "out", 1, 0x1000, 1, selectJSONFdSetData(5)[:1]},
		{"bytes", "out", 2, 0x2000, 1, selectJSONFdSetData(6)[:1]},
		{"struct", "out", 4, 0x3000, 16, selectJSONTimeval(1, 2)},
	}
	payload := selectJSONTLVPayload(t, want)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		EventFlags:    bpfEventFlagPayloadTLV,
		Args:          [6]uint64{8, 0x1000, 0x2000, 0, 0x3000},
		Ret:           1,
		DataLen:       uint32(len(payload)),
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	copy(eventRaw.StrArg[:], payload)

	scMeta := meta.Syscall{Name: "select"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != len(want) {
		t.Fatalf("PayloadSections = %d, want %d", len(ev.PayloadSections), len(want))
	}
	for i := range want {
		assertSelectJSONPayloadSection(t, ev.PayloadSections[i], want[i])
	}
}

func selectJSONTLVPayload(t *testing.T, wants []wantSelectJSONPayloadSection) []byte {
	t.Helper()
	var payload []byte
	for _, want := range wants {
		payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
			kind:    selectJSONTLVKind(t, want.kind),
			flags:   selectJSONTLVFlags(t, want.direction),
			arg:     uint16(want.argIndex),
			userPtr: want.userPtr,
			userLen: want.userLen,
			data:    want.data,
		})...)
	}
	return payload
}

func selectJSONTLVKind(t *testing.T, kind string) uint16 {
	t.Helper()
	switch handler.PayloadKind(kind) {
	case handler.PayloadKindBytes:
		return payloadTLVKindBytes
	case handler.PayloadKindStruct:
		return payloadTLVKindStruct
	default:
		t.Fatalf("unsupported select payload kind %q", kind)
		return 0
	}
}

func selectJSONTLVFlags(t *testing.T, direction string) uint16 {
	t.Helper()
	switch handler.PayloadDirection(direction) {
	case handler.PayloadDirectionIn:
		return 0
	case handler.PayloadDirectionOut:
		return payloadTLVFlagDirectionOut
	default:
		t.Fatalf("unsupported select payload direction %q", direction)
		return 0
	}
}

func TestSelectFdSetUserLenNormalizesSignExtendedNfds(t *testing.T) {
	if got := selectFdSetUserLen(0xffffffff00000005); got != 1 {
		t.Fatalf("selectFdSetUserLen(sign-extended 5) = %d, want 1", got)
	}
	if got := selectFdSetUserLen(0xffffffff00000401); got != selectPayloadFdSetSize {
		t.Fatalf("selectFdSetUserLen(sign-extended 1025) = %d, want %d", got, selectPayloadFdSetSize)
	}
	if got := selectFdSetUserLen(0xffffffffffffffff); got != 0 {
		t.Fatalf("selectFdSetUserLen(sign-extended -1) = %d, want 0", got)
	}
}

func assertSelectJSONPayloadSection(
	t *testing.T,
	got jsonPayloadSection,
	want wantSelectJSONPayloadSection,
) {
	t.Helper()
	if got.Kind != want.kind || got.Direction != want.direction || got.ArgIndex != want.argIndex {
		t.Fatalf("section metadata = %+v, want %+v", got, want)
	}
	if got.UserPtr != want.userPtr || got.UserLen != want.userLen {
		t.Fatalf("section bounds = %+v, want %+v", got, want)
	}
	if got.CopiedLen != uint32(len(want.data)) {
		t.Fatalf("section copied_len = %d, want %d", got.CopiedLen, len(want.data))
	}
	gotData := mustDecodeBase64(t, got.DataBase64)
	if string(gotData) != string(want.data) {
		t.Fatalf("section data = %v, want %v", gotData, want.data)
	}
}

func selectJSONFdSetData(fd int) []byte {
	data := make([]byte, selectPayloadFdSetSize)
	data[fd/8] = 1 << uint(fd%8)
	return data
}

func selectJSONTimeval(sec uint64, usec uint64) []byte {
	data := make([]byte, selectPayloadTimeoutSize)
	binary.LittleEndian.PutUint64(data[0:8], sec)
	binary.LittleEndian.PutUint64(data[8:16], usec)
	return data
}
