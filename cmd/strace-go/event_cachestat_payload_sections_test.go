package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/handler"
)

const (
	cachestatRangePayloadSize = 16
	cachestatStatsPayloadSize = 40
)

func TestJSONSyscallEventIncludesCachestatPayloadSections(t *testing.T) {
	rangeData := bytes.Repeat([]byte{0x11}, cachestatRangePayloadSize)
	statsData := bytes.Repeat([]byte{0x22}, cachestatStatsPayloadSize)
	args := [6]uint64{3, 0x1000, 0x2000, 0}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     1,
			userPtr: 0x1000,
			userLen: cachestatRangePayloadSize,
			data:    rangeData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     2,
			userPtr: 0x2000,
			userLen: cachestatStatsPayloadSize,
			data:    statsData,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "cachestat", bpfEventTypeExit, args, 0, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	assertCachestatJSONSection(t, ev.PayloadSections[0], 1, "in", 0x1000, rangeData)
	assertCachestatJSONSection(t, ev.PayloadSections[1], 2, "out", 0x2000, statsData)
}

func assertCachestatJSONSection(
	t *testing.T,
	got jsonPayloadSection,
	argIndex int,
	direction string,
	userPtr uint64,
	wantData []byte,
) {
	t.Helper()
	if got.Kind != "struct" || got.Direction != direction || got.ArgIndex != argIndex {
		t.Fatalf("cachestat section metadata = %+v", got)
	}
	if got.UserPtr != userPtr {
		t.Fatalf("cachestat section bounds = %+v", got)
	}
	if got.UserLen != uint32(len(wantData)) || got.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("cachestat section lengths = %+v, want %d", got, len(wantData))
	}
	if data := mustDecodeBase64(t, got.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("cachestat section data = %v, want %v", data, wantData)
	}
}

func TestSyscallEventContextMergesCachestatDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("cachestat")
	args := [6]uint64{3, 0x1000, 0x2000, 0}
	rangeData := bytes.Repeat([]byte{0x11}, cachestatRangePayloadSize)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     1,
		userPtr: args[1],
		userLen: cachestatRangePayloadSize,
		data:    rangeData,
	})
	enterEnvelope := testTLVSyscallEnvelope(t, "cachestat", bpfEventTypeEnter, args, 0, enterPayload)
	session.traceState().handleEnvelope(enterEnvelope)

	statsData := bytes.Repeat([]byte{0x22}, cachestatStatsPayloadSize)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     2,
		userPtr: args[2],
		userLen: cachestatStatsPayloadSize,
		data:    statsData,
	})
	exitEnvelope := testTLVSyscallEnvelope(t, "cachestat", bpfEventTypeExit, args, 0, exitPayload)
	exitUpdate := session.traceState().handleEnvelope(exitEnvelope)
	ev := newSyscallEventContextFromView(session, exitUpdate.syscallView, 101, exitUpdate.pendingEnter, exitUpdate.payloadSections)

	rangeSection, rangeOK := ev.handlerContext.Section(1, handler.PayloadKindStruct)
	if !rangeOK || rangeSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(rangeSection.Data, rangeData) {
		t.Fatalf("cachestat range section = %+v, %v; want pending enter IN struct", rangeSection, rangeOK)
	}
	statsSection, statsOK := ev.handlerContext.Section(2, handler.PayloadKindStruct)
	if !statsOK || statsSection.Direction != handler.PayloadDirectionOut || !bytes.Equal(statsSection.Data, statsData) {
		t.Fatalf("cachestat stats section = %+v, %v; want exit OUT struct", statsSection, statsOK)
	}
}
