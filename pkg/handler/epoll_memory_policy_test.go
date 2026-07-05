package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeEpollEvent(events uint32, data uint64) []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:4], events)
	binary.LittleEndian.PutUint64(buf[4:12], data)
	return buf
}

func makeEpollTimespec(sec int64, nsec uint64) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(buf[8:16], nsec)
	return buf
}

func newEpollPolicyContext(_ *fetchPolicyMemoryReader, name string) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       name,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       event.NewDecoder(),
	}
}

func TestEpollCtlFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(1, 7)}
	ctx := newEpollPolicyContext(reader, "epoll_ctl")
	ctx.Args = [6]uint64{3, 1, 4, 0x1000}

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 4 {
		t.Fatalf("ArgParts len = %d, want 4", len(got.ArgParts))
	}
	if got.ArgParts[3] != "0x1000" {
		t.Fatalf("epoll_ctl event = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollCtlIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(1, 7)}
	ctx := newEpollPolicyContext(reader, "epoll_ctl")
	ctx.Args = [6]uint64{3, 1, 4, 0x1000}
	ctx.ProbeRetEnter = 0

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 4 {
		t.Fatalf("ArgParts len = %d, want 4", len(got.ArgParts))
	}
	if got.ArgParts[3] != "0x1000" {
		t.Fatalf("epoll_ctl event = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollCtlUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(1, 9)}
	ctx := newEpollPolicyContext(reader, "epoll_ctl")
	ctx.Args = [6]uint64{3, 1, 4, 0x1000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 3, ProbeRet: 0, Data: makeEpollEvent(1, 7)},
	}

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 4 {
		t.Fatalf("ArgParts len = %d, want 4", len(got.ArgParts))
	}
	if !strings.Contains(got.ArgParts[3], "data={u32=7, u64=0x7}") {
		t.Fatalf("epoll_ctl event = %q", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollCtlDeleteDoesNotReadEvent(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(1, 7)}
	ctx := newEpollPolicyContext(reader, "epoll_ctl")
	ctx.Args = [6]uint64{3, 2, 4, 0x1000}

	got := (&EpollHandler{}).Handle(ctx)
	if got.ArgParts[3] != "0x1000" {
		t.Fatalf("epoll_ctl DEL event = %q, want pointer", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollWaitFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(1, 7)}
	ctx := newEpollPolicyContext(reader, "epoll_wait")
	ctx.Args = [6]uint64{5, 0x2000, 1, 1000}
	ctx.Ret = 1

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 4 {
		t.Fatalf("ArgParts len = %d, want 4", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x2000" {
		t.Fatalf("epoll_wait events = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollWaitIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(2, 9)}
	ctx := newEpollPolicyContext(reader, "epoll_wait")
	ctx.Args = [6]uint64{5, 0x2000, 1, 1000}
	ctx.Ret = 1
	ctx.ProbeRetExit = 0

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 4 {
		t.Fatalf("ArgParts len = %d, want 4", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x2000" {
		t.Fatalf("epoll_wait events = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollWaitUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(2, 9)}
	ctx := newEpollPolicyContext(reader, "epoll_wait")
	ctx.Args = [6]uint64{5, 0x2000, 1, 1000}
	ctx.Ret = 1
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeEpollEvent(1, 7)},
	}

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 4 {
		t.Fatalf("ArgParts len = %d, want 4", len(got.ArgParts))
	}
	if !strings.Contains(got.ArgParts[1], "data={u32=7, u64=0x7}") {
		t.Fatalf("epoll_wait events = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollPwait2TimeoutFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(1, 7)}
	ctx := newEpollPolicyContext(reader, "epoll_pwait2")
	ctx.Args = [6]uint64{5, 0x2000, 1, 0x3000, 0x4000, 8}
	ctx.Ret = 0

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 6 {
		t.Fatalf("ArgParts len = %d, want 6", len(got.ArgParts))
	}
	if got.ArgParts[3] != "0x3000" {
		t.Fatalf("epoll_pwait2 timeout = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollPwait2TimeoutIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollTimespec(99, 100)}
	ctx := newEpollPolicyContext(reader, "epoll_pwait2")
	ctx.Args = [6]uint64{5, 0x2000, 1, 0x3000, 0x4000, 8}
	ctx.Ret = 0
	ctx.ProbeRetEnter = 0

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 6 {
		t.Fatalf("ArgParts len = %d, want 6", len(got.ArgParts))
	}
	if got.ArgParts[3] != "0x3000" {
		t.Fatalf("epoll_pwait2 timeout = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollPwait2TimeoutUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollTimespec(99, 100)}
	ctx := newEpollPolicyContext(reader, "epoll_pwait2")
	ctx.Args = [6]uint64{5, 0x2000, 1, 0x3000, 0x4000, 8}
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 3, ProbeRet: 0, Data: makeEpollTimespec(9, 10)},
	}

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 6 {
		t.Fatalf("ArgParts len = %d, want 6", len(got.ArgParts))
	}
	if got.ArgParts[3] != "{tv_sec=9, tv_nsec=10}" {
		t.Fatalf("epoll_pwait2 timeout = %q", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollPwait2IgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(2, 9)}
	ctx := newEpollPolicyContext(reader, "epoll_pwait2")
	ctx.Args = [6]uint64{5, 0x2000, 1, 0, 0, 8}
	ctx.Ret = 1
	ctx.ProbeRetExit = 0

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 6 {
		t.Fatalf("ArgParts len = %d, want 6", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x2000" {
		t.Fatalf("epoll_pwait2 events = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestEpollPwait2UsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeEpollEvent(2, 9)}
	ctx := newEpollPolicyContext(reader, "epoll_pwait2")
	ctx.Args = [6]uint64{5, 0x2000, 1, 0, 0, 8}
	ctx.Ret = 1
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeEpollEvent(1, 7)},
	}

	got := (&EpollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 6 {
		t.Fatalf("ArgParts len = %d, want 6", len(got.ArgParts))
	}
	if !strings.Contains(got.ArgParts[1], "data={u32=7, u64=0x7}") {
		t.Fatalf("epoll_pwait2 events = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
