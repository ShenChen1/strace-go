package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func TestBpfMapDeleteElemUsesInputKeySnapshot(t *testing.T) {
	reader := &bpfPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfPolicyContext(reader, event.NewDecoder())
	ctx.Args[0] = 3
	ctx.PayloadSections = []PayloadSection{
		{
			Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 123,
			UserPtr: 0x4200, UserLen: 4, CopiedLen: 4, ProbeRet: 0,
			Data: []byte{7, 0, 0, 0},
		},
	}

	attr := makeBpfMapLookupAttr()
	binary.LittleEndian.PutUint64(attr[8:16], 0x4200)
	got := decodeBpfMapDeleteElem(ctx, attr, 24)
	if !strings.Contains(got, `key="\7\0\0\0"`) {
		t.Fatalf("decodeBpfMapDeleteElem() = %q, want key snapshot", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
