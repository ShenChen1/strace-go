package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func makeFutexWaitvData(val uint64, addr uint64, flags uint32) []byte {
	data := make([]byte, futexWaitvSize)
	binary.LittleEndian.PutUint64(data[0:8], val)
	binary.LittleEndian.PutUint64(data[8:16], addr)
	binary.LittleEndian.PutUint32(data[16:20], flags)
	return data
}

func makeUint64Snapshot(v uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, v)
	return data
}

func TestFutexTimeoutDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "futex",
		Args:          [6]uint64{0x2000, 0, 7, 0x1000},
		ProbeRetEnter: -1,
		Decoder:       decoder,
	}

	got := (&FutexHandler{}).Handle(ctx)
	if len(got.ArgParts) != 6 {
		t.Fatalf("ArgParts len = %d, want 6", len(got.ArgParts))
	}
	if got.ArgParts[3] != "0x1000" {
		t.Fatalf("timeout = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexTimeoutIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "futex",
		Args:          [6]uint64{0x2000, 0, 7, 0x1000},
		ProbeRetEnter: 0,
		Decoder:       decoder,
	}

	got := (&FutexHandler{}).Handle(ctx)
	if got.ArgParts[3] != "0x1000" {
		t.Fatalf("timeout = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexTimeoutUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "futex",
		Args:    [6]uint64{0x2000, 0, 7, 0x1000},
		Decoder: event.NewDecoder(),
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindStruct,
				Direction: PayloadDirectionIn,
				ArgIndex:  3,
				ProbeRet:  0,
				Data:      makeTimeStruct(9, 10),
			},
		},
	}

	got := (&FutexHandler{}).Handle(ctx)
	if got.ArgParts[3] != "{tv_sec=9, tv_nsec=10}" {
		t.Fatalf("timeout = %q", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexTimeoutOpSelection(t *testing.T) {
	tests := []struct {
		name string
		op   uint64
		want string
	}{
		{name: "wait bitset", op: futexCmdWaitBitset, want: "{tv_sec=9, tv_nsec=10}"},
		{name: "lock pi", op: futexCmdLockPI, want: "{tv_sec=9, tv_nsec=10}"},
		{name: "futex fd", op: 2, want: "0x1000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{
				Pid:     1234,
				Tid:     1234,
				SysName: "futex",
				Args:    [6]uint64{0x2000, tt.op, 7, 0x1000},
				Decoder: event.NewDecoder(),
				PayloadSections: []PayloadSection{
					{
						Kind:      PayloadKindStruct,
						Direction: PayloadDirectionIn,
						ArgIndex:  3,
						ProbeRet:  0,
						Data:      makeTimeStruct(9, 10),
					},
				},
			}

			got := (&FutexHandler{}).Handle(ctx)
			if got.ArgParts[3] != tt.want {
				t.Fatalf("timeout = %q, want %q", got.ArgParts[3], tt.want)
			}
		})
	}
}

func TestFutexWaitvDoesNotProbeLengthWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFutexWaitvData(1, 0x3000, 0)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Args:          [6]uint64{0x1000, 2},
		ProbeRetEnter: 0,
		Decoder:       decoder,
		ScMeta:        meta.Syscall{Name: "futex_waitv"},
	}

	got := formatFutexWaitvArray(ctx, 0, 0x1000, 2)
	if got != "0x1000" {
		t.Fatalf("formatFutexWaitvArray() = %q, want pointer without payload section", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexWaitvIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFutexWaitvData(1, 0x3000, 0)}
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Args:          [6]uint64{0x1000, 2},
		ProbeRetEnter: 0,
		Decoder:       event.NewDecoder(),
		ScMeta:        meta.Syscall{Name: "futex_waitv"},
	}

	got := formatFutexWaitvArray(ctx, 0, 0x1000, 2)
	if got != "0x1000" {
		t.Fatalf("formatFutexWaitvArray() = %q, want section-only pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexWaitvUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFutexWaitvData(1, 0x3000, 0)}
	buf := append(makeFutexWaitvData(1, 0x3000, 0), makeFutexWaitvData(2, 0x4000, 0)...)
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Args:    [6]uint64{0x1000, 2},
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "futex_waitv"},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindStruct,
				Direction: PayloadDirectionIn,
				ArgIndex:  0,
				ProbeRet:  0,
				Data:      buf,
			},
		},
	}

	got := formatFutexWaitvArray(ctx, 0, 0x1000, 2)
	if !strings.Contains(got, "val=0x2") {
		t.Fatalf("formatFutexWaitvArray() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexWaitTimeoutUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(1, 2)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Ret:     0,
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "futex_wait"},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindStruct,
				Direction: PayloadDirectionIn,
				ArgIndex:  4,
				ProbeRet:  0,
				Data:      makeTimeStruct(1, 2),
			},
		},
	}

	got, ok := decodeTimespec(ctx, 4, "struct __kernel_timespec *", 0x3000)
	if !ok || got != "{tv_sec=1, tv_nsec=2}" {
		t.Fatalf("decodeTimespec() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFutexWaitvTimeoutUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(3, 4)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Ret:     0,
		Args:    [6]uint64{0x1000, 1, 0, 0x4000},
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "futex_waitv"},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindStruct,
				Direction: PayloadDirectionIn,
				ArgIndex:  3,
				ProbeRet:  0,
				Data:      makeTimeStruct(3, 4),
			},
		},
	}

	got, ok := decodeTimespec(ctx, 3, "struct __kernel_timespec *", 0x4000)
	if !ok || got != "{tv_sec=3, tv_nsec=4}" {
		t.Fatalf("decodeTimespec() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func newArchPrctlPolicyContext(decoder *event.Decoder) *Context {
	return &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "arch_prctl",
		Args:         [6]uint64{0x1003, 0x2000},
		Ret:          0,
		ProbeRetExit: -1,
		Decoder:      decoder,
		ScMeta: meta.Syscall{
			Args:     []string{"option", "arg2"},
			ArgTypes: []string{"int", "unsigned long"},
		},
	}
}

func TestArchPrctlDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0x1234)}
	decoder := event.NewDecoder()
	ctx := newArchPrctlPolicyContext(decoder)

	got := (&ArchPrctlHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if got.ArgParts[1] != "[NULL]" {
		t.Fatalf("arch_prctl arg = %q, want NULL without payload section", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestArchPrctlIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0x1234)}
	decoder := event.NewDecoder()
	ctx := newArchPrctlPolicyContext(decoder)
	ctx.ProbeRetExit = 0

	got := (&ArchPrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "[NULL]" {
		t.Fatalf("arch_prctl arg = %q, want payload-section fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestArchPrctlUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeUint64Snapshot(0x1234)}
	ctx := newArchPrctlPolicyContext(event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeUint64Snapshot(0x5678)},
	}

	got := (&ArchPrctlHandler{}).Handle(ctx)
	if got.ArgParts[1] != "[0x5678]" {
		t.Fatalf("arch_prctl arg = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
