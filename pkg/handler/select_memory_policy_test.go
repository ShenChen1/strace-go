package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

const selectTestBufSize = BpfExitArgOffset + pollSnapshotLimit

const (
	legacySelectTimeoutOffset  = 384
	legacySelectExitTimeoutOff = 1408
	legacyPpollTimeoutOffset   = BpfMiscArgOffset
)

func makeFdSetData(fd int) []byte {
	data := make([]byte, fdSetSnapshotSize)
	data[fd/8] = 1 << uint(fd%8)
	return data
}

func makePollfdData(fd int32, events uint16, revents uint16) []byte {
	data := make([]byte, pollFdSize)
	binary.LittleEndian.PutUint32(data[0:4], uint32(fd))
	binary.LittleEndian.PutUint16(data[4:6], events)
	binary.LittleEndian.PutUint16(data[6:8], revents)
	return data
}

func makeSelectTime(sec int64, nsec uint64) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(data[8:16], nsec)
	return data
}

func newSelectPolicyContext(reader *fetchPolicyMemoryReader, name string) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       name,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       event.NewDecoder(),
		StrArgBuf:     make([]byte, selectTestBufSize),
	}
}

func putSelectSnapshot(ctx *Context, offset int, data []byte) {
	copy(ctx.StrArgBuf[offset:], data)
	end := uint32(offset + len(data))
	if ctx.DataLen < end {
		ctx.DataLen = end
	}
}

func TestSelectFdSetsFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFdSetData(3)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{8, 0x1000, 0, 0, 0}

	got := (&SelectHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 {
		t.Fatalf("ArgParts len = %d, want 5", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("select readfds = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectFdSetsIgnoreLegacyEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFdSetData(7)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{8, 0x1000, 0, 0, 0}
	ctx.ProbeRetEnter = 0
	putSelectSnapshot(ctx, BpfEnterArgOffset, makeFdSetData(3))

	got := (&SelectHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("select readfds = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectFdSetsUsePayloadBytesSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFdSetData(7)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{8, 0x1000, 0, 0, 0}
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeFdSetData(3)},
	}

	got := (&SelectHandler{}).Handle(ctx)
	if got.ArgParts[1] != "[3]" {
		t.Fatalf("select readfds = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectTimeoutFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(9, 10)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{0, 0, 0, 0, 0x3000}

	got := (&SelectHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 {
		t.Fatalf("ArgParts len = %d, want 5", len(got.ArgParts))
	}
	if got.ArgParts[4] != "0x3000" {
		t.Fatalf("select timeout = %q, want pointer fallback", got.ArgParts[4])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectTimeoutIgnoresLegacyEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(99, 100)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{0, 0, 0, 0, 0x3000}
	ctx.ProbeRetEnter = 0
	putSelectSnapshot(ctx, legacySelectTimeoutOffset, makeSelectTime(9, 10))

	got := (&SelectHandler{}).Handle(ctx)
	if got.ArgParts[4] != "0x3000" {
		t.Fatalf("select timeout = %q, want pointer fallback", got.ArgParts[4])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectTimeoutUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(99, 100)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{0, 0, 0, 0, 0x3000}
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 4, ProbeRet: 0, Data: makeSelectTime(9, 10)},
	}

	got := (&SelectHandler{}).Handle(ctx)
	if got.ArgParts[4] != "{tv_sec=9, tv_usec=10}" {
		t.Fatalf("select timeout = %q", got.ArgParts[4])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectExitIgnoresLegacyExitSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFdSetData(7)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{8, 0x1000, 0, 0, 0}
	ctx.Ret = 1
	ctx.ProbeRetExit = 0
	putSelectSnapshot(ctx, BpfExitArgOffset, makeFdSetData(3))

	got := (&SelectHandler{}).Handle(ctx)
	if got.ReturnDesc != "" {
		t.Fatalf("ReturnDesc = %q, want empty legacy fallback", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectExitUsesPayloadBytesSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFdSetData(7)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{8, 0x1000, 0, 0, 0}
	ctx.Ret = 1
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeFdSetData(7)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeFdSetData(3)},
	}

	got := (&SelectHandler{}).Handle(ctx)
	if got.ReturnDesc != "in [3]" {
		t.Fatalf("ReturnDesc = %q", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectExitTimeoutIgnoresLegacyExitSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(99, 100)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{0, 0, 0, 0, 0x3000}
	ctx.Ret = 1
	ctx.ProbeRetExit = 0
	putSelectSnapshot(ctx, legacySelectExitTimeoutOff, makeSelectTime(1, 2))

	got := (&SelectHandler{}).Handle(ctx)
	if got.ReturnDesc != "" {
		t.Fatalf("ReturnDesc = %q, want empty legacy fallback", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestSelectExitTimeoutUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(99, 100)}
	ctx := newSelectPolicyContext(reader, "select")
	ctx.Args = [6]uint64{0, 0, 0, 0, 0x3000}
	ctx.Ret = 1
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 4, ProbeRet: 0, Data: makeSelectTime(9, 10)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 4, ProbeRet: 0, Data: makeSelectTime(1, 2)},
	}

	got := (&SelectHandler{}).Handle(ctx)
	if got.ReturnDesc != "left {tv_sec=1, tv_usec=2}" {
		t.Fatalf("ReturnDesc = %q", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(4, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 1, 1000}

	got := (&PollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 3 {
		t.Fatalf("ArgParts len = %d, want 3", len(got.ArgParts))
	}
	if got.ArgParts[0] != "0x2000" {
		t.Fatalf("poll fds = %q, want pointer fallback", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollIgnoresLegacyEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(7, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 1, 1000}
	ctx.ProbeRetEnter = 0
	putSelectSnapshot(ctx, BpfEnterArgOffset, makePollfdData(4, 1, 0))

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[0] != "0x2000" {
		t.Fatalf("poll fds = %q, want pointer fallback", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(7, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 1, 1000}
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 0, ProbeRet: 0, Data: makePollfdData(4, 1, 0)},
	}

	got := (&PollHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[0], "{fd=4") {
		t.Fatalf("poll fds = %q", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollExitIgnoresLegacyExitSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(4, 0, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 1, 1000}
	ctx.Ret = 1
	ctx.ProbeRetExit = 0
	putSelectSnapshot(ctx, BpfExitArgOffset, makePollfdData(4, 0, 1))

	got := (&PollHandler{}).Handle(ctx)
	if got.ReturnDesc != "" {
		t.Fatalf("ReturnDesc = %q, want empty legacy fallback", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollExitUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(4, 0, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 1, 1000}
	ctx.Ret = 1
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 0, ProbeRet: 0, Data: makePollfdData(4, 1, 0)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: makePollfdData(4, 0, 1)},
	}

	got := (&PollHandler{}).Handle(ctx)
	if !strings.Contains(got.ArgParts[0], "{fd=4") {
		t.Fatalf("poll fds = %q", got.ArgParts[0])
	}
	if !strings.Contains(got.ReturnDesc, "revents=") {
		t.Fatalf("ReturnDesc = %q", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPpollTimeoutFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(9, 10)}
	ctx := newSelectPolicyContext(reader, "ppoll")
	ctx.Args = [6]uint64{0, 0, 0x3000}

	got := (&PollHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 {
		t.Fatalf("ArgParts len = %d, want 5", len(got.ArgParts))
	}
	if got.ArgParts[2] != "0x3000" {
		t.Fatalf("ppoll timeout = %q, want pointer fallback", got.ArgParts[2])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPpollTimeoutUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(99, 100)}
	ctx := newSelectPolicyContext(reader, "ppoll")
	ctx.Args = [6]uint64{0, 0, 0x3000}
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 2, ProbeRet: 0, Data: makeSelectTime(9, 10)},
	}

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[2] != "{tv_sec=9, tv_nsec=10}" {
		t.Fatalf("ppoll timeout = %q", got.ArgParts[2])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPpollTimeoutIgnoresLegacyEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(99, 100)}
	ctx := newSelectPolicyContext(reader, "ppoll")
	ctx.Args = [6]uint64{0, 0, 0x3000}
	ctx.ProbeRetEnter = 0
	putSelectSnapshot(ctx, legacyPpollTimeoutOffset, makeSelectTime(9, 10))

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[2] != "0x3000" {
		t.Fatalf("ppoll timeout = %q, want pointer fallback", got.ArgParts[2])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
