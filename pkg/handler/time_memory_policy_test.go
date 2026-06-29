package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeTimexStruct(modes uint32) []byte {
	data := make([]byte, 208)
	binary.LittleEndian.PutUint32(data[0:4], modes)
	return data
}

func putTimeSnapshot(ctx *Context, offset int, data []byte) {
	copy(ctx.StrArgBuf[offset:], data)
	end := uint32(offset + len(data))
	if ctx.DataLen < end {
		ctx.DataLen = end
	}
}

func TestTimeHandlerClockGettimeDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "clock_gettime",
		Args:         [6]uint64{0, 0x1000},
		Ret:          0,
		ProbeRetExit: -1,
		Decoder:      decoder,
		StrArgBuf:    make([]byte, BpfExitArgOffset+208),
	}

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("clock_gettime timespec = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerClockSettimeUsesEnterSnapshotWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	decoder := event.NewDecoder()
	buf := make([]byte, BpfExitArgOffset+208)
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "clock_settime",
		Args:          [6]uint64{0, 0x1000},
		Ret:           0,
		ProbeRetEnter: 0,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		StrArgBuf:     buf,
	}
	putTimeSnapshot(ctx, BpfEnterArgOffset, makeTimeStruct(5, 6))

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if got.ArgParts[1] != "{tv_sec=5, tv_nsec=6}" {
		t.Fatalf("clock_settime timespec = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerAdjtimexDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimexStruct(7)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "adjtimex",
		Args:         [6]uint64{0x1000},
		Ret:          -1,
		ProbeRetExit: -1,
		Decoder:      decoder,
		StrArgBuf:    make([]byte, BpfExitArgOffset+208),
	}

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 1 {
		t.Fatalf("ArgParts len = %d, want 1", len(got.ArgParts))
	}
	if got.ArgParts[0] != "0x1000" {
		t.Fatalf("adjtimex timex = %q, want pointer fallback", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerAdjtimexUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimexStruct(7)}
	decoder := event.NewDecoder()
	buf := make([]byte, BpfExitArgOffset+208)
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "adjtimex",
		Args:         [6]uint64{0x1000},
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
		StrArgBuf:    buf,
	}
	putTimeSnapshot(ctx, BpfExitArgOffset, makeTimexStruct(7))

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 1 {
		t.Fatalf("ArgParts len = %d, want 1", len(got.ArgParts))
	}
	if !strings.HasPrefix(got.ArgParts[0], "{modes=7,") {
		t.Fatalf("adjtimex timex = %q", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerClockAdjtimeUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimexStruct(9)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "clock_adjtime",
		Args:         [6]uint64{0, 0x1000},
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
		StrArgBuf:    make([]byte, BpfExitArgOffset+208),
	}
	putTimeSnapshot(ctx, BpfExitArgOffset, makeTimexStruct(9))

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if !strings.HasPrefix(got.ArgParts[1], "{modes=9,") {
		t.Fatalf("clock_adjtime timex = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
