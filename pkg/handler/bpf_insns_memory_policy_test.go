package handler

import (
	"encoding/binary"
	"errors"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

type bpfInsnsPolicyMemoryReader struct {
	data  map[uint64][]byte
	reads int
}

func (r *bpfInsnsPolicyMemoryReader) Read(_ int, addr uint64, size int) ([]byte, error) {
	r.reads++
	data, ok := r.data[addr]
	if !ok {
		return nil, errors.New("unreadable address")
	}
	if size >= 0 && size < len(data) {
		data = data[:size]
	}
	return append([]byte(nil), data...), nil
}

func newBpfInsnsPolicyContext(reader *bpfInsnsPolicyMemoryReader, decoder *event.Decoder, verbose bool) *Context {
	return &Context{
		Tid:     1234,
		Decoder: decoder,
		Opts:    &cli.Options{Verbose: verbose},
	}
}

func makeBpfExitInsn() []byte {
	return []byte{0x95, 0, 0, 0, 0, 0, 0, 0}
}

func makeBpfVerboseExitInsn() []byte {
	data := []byte{0x95, 0xba, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(data[2:4], 0xdead)
	binary.LittleEndian.PutUint32(data[4:8], 0xbadc0ded)
	return data
}

func TestBpfInsnsNonVerboseDoesNotReadMemory(t *testing.T) {
	reader := &bpfInsnsPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfExitInsn(),
	}}
	ctx := newBpfInsnsPolicyContext(reader, event.NewDecoder(), false)

	got := decodeBpfInsns(ctx, 0x1000, 1)
	if got != "insns=0x1000" {
		t.Fatalf("decodeBpfInsns() = %q, want pointer output", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfInsnsDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &bpfInsnsPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfExitInsn(),
	}}
	decoder := event.NewDecoder()
	ctx := newBpfInsnsPolicyContext(reader, decoder, true)

	got := decodeBpfInsns(ctx, 0x1000, 1)
	if got != "insns=0x1000" {
		t.Fatalf("decodeBpfInsns() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfInsnsDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &bpfInsnsPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBpfExitInsn(),
	}}
	ctx := newBpfInsnsPolicyContext(reader, event.NewDecoder(), true)

	got := decodeBpfInsns(ctx, 0x1000, 1)
	if got != "insns=0x1000" {
		t.Fatalf("decodeBpfInsns() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBpfInsnsVerboseUsesNestedPayloadSection(t *testing.T) {
	reader := &bpfInsnsPolicyMemoryReader{data: map[uint64][]byte{}}
	ctx := newBpfInsnsPolicyContext(reader, event.NewDecoder(), true)
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindBytes,
			Direction: PayloadDirectionIn,
			ArgIndex:  bpfProgLoadInsnsPayloadArg,
			UserPtr:   0x1000,
			UserLen:   8,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      makeBpfVerboseExitInsn(),
		},
	}

	got := decodeBpfInsns(ctx, 0x1000, 1)
	want := "insns=[{code=BPF_JMP|BPF_K|BPF_EXIT, dst_reg=BPF_REG_10, src_reg=0xb /* BPF_REG_??? */, off=-8531, imm=0xbadc0ded}]"
	if got != want {
		t.Fatalf("decodeBpfInsns() = %q, want %q", got, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
