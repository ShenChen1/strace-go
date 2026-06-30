package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesCachestatPayloadSections(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x1000, 0x2000, 0},
		Ret:           0,
		DataLen:       handler.BpfExitArgOffset + cachestatStatsPayloadSize,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	rangeData := bytes.Repeat([]byte{0x11}, cachestatRangePayloadSize)
	statsData := bytes.Repeat([]byte{0x22}, cachestatStatsPayloadSize)
	copy(eventRaw.StrArg[cachestatRangePayloadOffset:], rangeData)
	copy(eventRaw.StrArg[handler.BpfExitArgOffset:], statsData)

	scMeta := meta.Syscall{Name: "cachestat"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertCachestatJSONSection(t, ev.PayloadSections[0], 1, "in", cachestatRangePayloadOffset, 0x1000, rangeData)
	assertCachestatJSONSection(t, ev.PayloadSections[1], 2, "out", handler.BpfExitArgOffset, 0x2000, statsData)
}

func assertCachestatJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	argIndex int,
	direction string,
	offset int,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != "struct" || got.Direction != direction || got.ArgIndex != argIndex {
		t.Fatalf("cachestat section metadata = %+v", got)
	}
	if got.Offset != uint32(offset) || got.UserPtr != userPtr {
		t.Fatalf("cachestat section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("cachestat section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("cachestat section data = %v, want %v", data, wantData)
	}
}
