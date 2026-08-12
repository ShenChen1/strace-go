package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
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

func newSignalPolicyContext(_ *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "rt_sigprocmask",
		Args:          [6]uint64{0, 0, 0, 8},
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		Meta:          meta.NewCatalog("abbrev"),
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

func TestSignalSigsetIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0

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
	ctx.Args[3] = 8
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

func TestSignalSigprocmaskInvalidSigsetSizePrintsPointer(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.Args[3] = 16
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeSigsetData(1)},
	}

	got := (&SignalHandler{}).formatSigsetArg(ctx, 1, "nset", 0x1000)
	if got != "0x1000" {
		t.Fatalf("formatSigsetArg() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSignalSigprocmaskFailedReadPrintsPointer(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.Ret = -14

	got := (&SignalHandler{}).formatSigsetArg(ctx, 1, "nset", 0x1000)
	if got != "0x1000" {
		t.Fatalf("formatSigsetArg() = %q, want pointer fallback", got)
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

func TestSignalOldsetIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigsetData(0)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.Ret = 0
	ctx.ProbeRetExit = 0

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

func TestSignalSigactionIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigactionData(1, 1)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0

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

func TestSignalFDHandlerUsesEventTimeMask(t *testing.T) {
	h, ok := NewRegistry().Resolve("signalfd4").(*SignalHandler)
	if !ok {
		t.Fatal("signalfd4 must use SignalHandler")
	}
	ctx := &Context{
		SysName: "signalfd4",
		ScMeta: meta.Syscall{
			Name:     "signalfd4",
			Args:     []string{"ufd", "user_mask", "sizemask", "flags"},
			ArgTypes: []string{"int", "sigset_t *", "size_t", "int"},
		},
		Meta: meta.NewCatalog("abbrev"),
		Args: [6]uint64{^uint64(0), 0x1000, 8, 0x80000},
		PayloadSections: []PayloadSection{{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			ProbeRet:  0,
			Data:      makeSigsetData(1 << 11),
		}},
	}
	if got := h.formatSigsetArg(ctx, 1, "user_mask", ctx.Args[1]); got != "[USR2]" {
		t.Fatalf("signalfd mask = %q, want [USR2]", got)
	}
}

func TestSignalFDHandlerUsesPointerOnInvalidMaskSnapshot(t *testing.T) {
	h, ok := NewRegistry().Resolve("signalfd4").(*SignalHandler)
	if !ok {
		t.Fatal("signalfd4 must use SignalHandler")
	}
	ctx := &Context{
		SysName: "signalfd4",
		ScMeta: meta.Syscall{
			Name:     "signalfd4",
			Args:     []string{"ufd", "user_mask", "sizemask", "flags"},
			ArgTypes: []string{"int", "sigset_t *", "size_t", "int"},
		},
		Meta: meta.NewCatalog("abbrev"),
		Args: [6]uint64{^uint64(0), 0x1000, 16, 0},
		Ret:  -14,
	}
	if got := h.formatSigsetArg(ctx, 1, "user_mask", ctx.Args[1]); got != "0x1000" {
		t.Fatalf("invalid signalfd mask = %q, want pointer", got)
	}
}

func TestSignalSigactionIgnoresProbeSuccessWithoutPayloadSectionOnExit(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSigactionData(0, 0)}
	decoder := event.NewDecoder()
	ctx := newSignalPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0

	got := (&SignalHandler{}).formatSigactionArg(ctx, 2, "oact", 0x2000)
	if got != "0x2000" {
		t.Fatalf("formatSigactionArg() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
