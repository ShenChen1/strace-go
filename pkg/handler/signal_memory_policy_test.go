package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeSigsetData(mask uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, mask)
	return data
}

func makeSigactionData(handler uint64, mask uint64) []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[0:8], handler)
	binary.LittleEndian.PutUint64(data[24:32], mask)
	return data
}

func newSignalPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "rt_sigprocmask",
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		StrArgBuf:     make([]byte, BpfExitArgOffset+32),
	}
}

func putSignalSnapshot(ctx *Context, offset int, data []byte) {
	copy(ctx.StrArgBuf[offset:], data)
	end := uint32(offset + len(data))
	if ctx.DataLen < end {
		ctx.DataLen = end
	}
}

func TestSignalSigsetDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)

	got := (&SignalHandler{}).formatSigsetArg(ctx, 1, "nset", 0x1000)
	if got != "[]" {
		t.Fatalf("formatSigsetArg() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalSigsetIgnoresLegacyEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0
	putSignalSnapshot(ctx, BpfEnterArgOffset, makeSigsetData(1))

	got := (&SignalHandler{}).formatSigsetArg(ctx, 1, "nset", 0x1000)
	if got != "[]" {
		t.Fatalf("formatSigsetArg() = %q, want empty set fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalSigsetUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(0)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeSigsetData(1)},
	}

	got := (&SignalHandler{}).formatSigsetArg(ctx, 1, "nset", 0x1000)
	if got != "[HUP]" {
		t.Fatalf("formatSigsetArg() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalOldsetDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.Ret = 0

	got := (&SignalHandler{}).formatSigsetArg(ctx, 2, "oset", 0x1000)
	if got != "0x1000" {
		t.Fatalf("formatSigsetArg() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalOldsetIgnoresLegacyExitSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(0)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.Ret = 0
	ctx.ProbeRetExit = 0
	putSignalSnapshot(ctx, BpfExitArgOffset, makeSigsetData(1))

	got := (&SignalHandler{}).formatSigsetArg(ctx, 2, "oset", 0x1000)
	if got != "0x1000" {
		t.Fatalf("formatSigsetArg() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalOldsetUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(0)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.Ret = 0
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: 0, Data: makeSigsetData(1)},
	}

	got := (&SignalHandler{}).formatSigsetArg(ctx, 2, "oset", 0x1000)
	if got != "[HUP]" {
		t.Fatalf("formatSigsetArg() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalSigactionDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigactionData(1, 1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)

	got := (&SignalHandler{}).formatSigactionArg(ctx, 1, "act", 0x2000)
	if got != "0x2000" {
		t.Fatalf("formatSigactionArg() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalSigactionUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigactionData(0, 0)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeSigactionData(1, 1)},
	}

	got := (&SignalHandler{}).formatSigactionArg(ctx, 1, "act", 0x2000)
	if !strings.Contains(got, "sa_handler=SIG_IGN") || !strings.Contains(got, "sa_mask=[HUP]") {
		t.Fatalf("formatSigactionArg() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalSigactionIgnoresLegacyEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigactionData(1, 1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0
	putSignalSnapshot(ctx, BpfEnterArgOffset, makeSigactionData(1, 1))

	got := (&SignalHandler{}).formatSigactionArg(ctx, 1, "act", 0x2000)
	if got != "0x2000" {
		t.Fatalf("formatSigactionArg() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalOldSigactionUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigactionData(0, 0)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: 0, Data: makeSigactionData(1, 1)},
	}

	got := (&SignalHandler{}).formatSigactionArg(ctx, 2, "oact", 0x2000)
	if !strings.Contains(got, "sa_handler=SIG_IGN") || !strings.Contains(got, "sa_mask=[HUP]") {
		t.Fatalf("formatSigactionArg() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalSigactionIgnoresLegacyExitSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigactionData(0, 0)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putSignalSnapshot(ctx, BpfExitArgOffset, makeSigactionData(1, 1))

	got := (&SignalHandler{}).formatSigactionArg(ctx, 2, "oact", 0x2000)
	if got != "0x2000" {
		t.Fatalf("formatSigactionArg() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
