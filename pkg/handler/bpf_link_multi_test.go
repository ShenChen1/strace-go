package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

const (
	testBpfTracingMultiIDsPayloadArg     = 145
	testBpfTracingMultiCookiesPayloadArg = 146
)

func makeBpfUprobeMultiAttrWithPathFD() []byte {
	data := make([]byte, 64)
	copy(data, makeBpfUprobeMultiAttr())
	binary.LittleEndian.PutUint32(data[60:64], 9)
	return data
}

func makeBpfTracingMultiAttr(attachType uint32) []byte {
	data := make([]byte, 36)
	binary.LittleEndian.PutUint32(data[8:12], attachType)
	binary.LittleEndian.PutUint64(data[16:24], 0x1000)
	binary.LittleEndian.PutUint64(data[24:32], 0x2000)
	binary.LittleEndian.PutUint32(data[32:36], 4)
	return data
}

func TestBpfUprobeMultiDecodesPathFD(t *testing.T) {
	ctx := newBpfPolicyContext(&bpfPolicyMemoryReader{}, event.NewDecoder())

	got := decodeBpfLinkCreate(ctx, makeBpfUprobeMultiAttrWithPathFD(), 64)
	if !strings.Contains(got, "path_fd=9") {
		t.Fatalf("decodeBpfLinkCreate() = %q, missing path_fd", got)
	}
}

func TestBpfTracingMultiUsesEventPayloadSections(t *testing.T) {
	ctx := newBpfPolicyContext(&bpfPolicyMemoryReader{}, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{
			Kind: PayloadKindBytes, Direction: PayloadDirectionIn,
			ArgIndex: testBpfTracingMultiIDsPayloadArg, UserPtr: 0x1000,
			UserLen: 16, CopiedLen: 16, ProbeRet: 0,
			Data: makeBpfU32Array(1, 42, 4207869677, 3134983661),
		},
		{
			Kind: PayloadKindBytes, Direction: PayloadDirectionIn,
			ArgIndex: testBpfTracingMultiCookiesPayloadArg, UserPtr: 0x2000,
			UserLen: 32, CopiedLen: 32, ProbeRet: 0,
			Data: makeBpfU64Array(0, 0xdeadc0defacecafe, 0x123456789abcdef0, 0xfeedface00000001),
		},
	}

	got := decodeBpfLinkCreate(ctx, makeBpfTracingMultiAttr(59), 36)
	for _, want := range []string{
		"tracing_multi={ids=[1, 42, 4207869677, 3134983661]",
		"cookies=[0, 0xdeadc0defacecafe, 0x123456789abcdef0, 0xfeedface00000001]",
		"cnt=4}",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("decodeBpfLinkCreate() = %q, missing %q", got, want)
		}
	}
}

func TestBpfTracingMultiFallsBackToPointersWithoutPayload(t *testing.T) {
	ctx := newBpfPolicyContext(&bpfPolicyMemoryReader{}, event.NewDecoder())

	got := decodeBpfLinkCreate(ctx, makeBpfTracingMultiAttr(61), 36)
	for _, want := range []string{"ids=0x1000", "cookies=0x2000", "cnt=4}"} {
		if !strings.Contains(got, want) {
			t.Fatalf("decodeBpfLinkCreate() = %q, missing %q", got, want)
		}
	}
}
