package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBpfProgLoadLogAttr() []byte {
	data := make([]byte, 144)
	binary.LittleEndian.PutUint32(data[28:32], 32)
	binary.LittleEndian.PutUint64(data[32:40], 0x4000)
	return data
}

func TestBpfProgLoadFailurePrefersVerifierLogOutPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: []byte("reader-must-not-run"),
	}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Ret = -22
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: bpfProgLoadLogBufPayloadArg, UserPtr: 0x4000, UserLen: 32, CopiedLen: 32, ProbeRet: 0, Data: []byte("initial-log")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: bpfProgLoadLogBufPayloadArg, UserPtr: 0x4000, UserLen: 13, CopiedLen: 13, ProbeRet: 0, Data: []byte("verifier-log")},
	}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadLogAttr(), 144)
	if !strings.Contains(got, `log_buf="verifier-log"`) || strings.Contains(got, "initial-log") {
		t.Fatalf("decodeBpfProgLoad() = %q, want verifier OUT snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfProgLoadFailureFallsBackToEnterLogWithoutOutPayload(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Ret = -22
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: bpfProgLoadLogBufPayloadArg, UserPtr: 0x4000, UserLen: 11, CopiedLen: 11, ProbeRet: 0, Data: []byte("initial-log")},
	}

	got := decodeBpfProgLoad(ctx, makeBpfProgLoadLogAttr(), 144)
	if !strings.Contains(got, `log_buf="initial-log"`) {
		t.Fatalf("decodeBpfProgLoad() = %q, want enter snapshot fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
