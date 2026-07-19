package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/cli"
)

func makePpollSigsetData(mask uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, mask)
	return data
}

func TestPollStringLimitZeroAbbreviatesCapturedArrays(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(7, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 2, 42}
	ctx.Ret = 1
	ctx.Opts = &cli.Options{StringLimit: 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 0, ProbeRet: 0, Data: makePollfdData(4, 1, 0)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: makePollfdData(4, 0, 1)},
	}

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[0] != "[...]" {
		t.Fatalf("poll fds = %q, want abbreviated array", got.ArgParts[0])
	}
	if got.ReturnDesc != "[...]" {
		t.Fatalf("ReturnDesc = %q, want abbreviated array", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollStringLimitZeroKeepsPointerFallbackWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(7, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 1, 0}
	ctx.Opts = &cli.Options{StringLimit: 0}

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[0] != "0x2000" {
		t.Fatalf("poll fds = %q, want pointer fallback", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollStringLimitOneShowsFirstArrayElement(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(7, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 3, 42}
	ctx.Ret = 2
	ctx.Opts = &cli.Options{StringLimit: 1}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  0,
			ProbeRet:  0,
			Data: append(append(
				makePollfdData(4, 1, 0),
				makePollfdData(5, 4, 0)...),
				makePollfdData(6, 4, 0)...),
		},
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionOut,
			ArgIndex:  0,
			ProbeRet:  0,
			Data: append(append(
				makePollfdData(4, 0, 1),
				makePollfdData(5, 0, 4)...),
				makePollfdData(6, 0, 0)...),
		},
	}

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[0] != "[{fd=4, events=POLLIN}, ...]" {
		t.Fatalf("poll fds = %q, want first element plus ellipsis", got.ArgParts[0])
	}
	if got.ReturnDesc != "[{fd=4, revents=POLLIN}, ...]" {
		t.Fatalf("ReturnDesc = %q, want first revent plus ellipsis", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollStringLimitOneDoesNotAppendReturnEllipsisForSingleRevent(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(7, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 3, 42}
	ctx.Ret = 1
	ctx.Opts = &cli.Options{StringLimit: 1}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  0,
			ProbeRet:  0,
			Data: append(append(
				makePollfdData(4, 1, 0),
				makePollfdData(5, 4, 0)...),
				makePollfdData(6, 4, 0)...),
		},
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionOut,
			ArgIndex:  0,
			ProbeRet:  0,
			Data: append(append(
				makePollfdData(4, 0, 0),
				makePollfdData(5, 0, 4)...),
				makePollfdData(6, 0, 0)...),
		},
	}

	got := (&PollHandler{}).Handle(ctx)
	if got.ReturnDesc != "[{fd=5, revents=POLLOUT}]" {
		t.Fatalf("ReturnDesc = %q, want single revent without ellipsis", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollStringLimitOneKeepsPartialPayloadMarker(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(7, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x1ff8, 2, 0}
	ctx.Opts = &cli.Options{StringLimit: 1}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  0,
			UserPtr:   0x1ff8,
			UserLen:   16,
			CopiedLen: 8,
			ProbeRet:  0,
			Data:      makePollfdData(-5, 0, 0),
		},
	}

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[0] != "[{fd=-5}, ... /* 0x2000 */]" {
		t.Fatalf("poll fds = %q, want partial marker", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPollVerboseOverridesStringLimitArrayAbbreviation(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makePollfdData(7, 1, 0)}
	ctx := newSelectPolicyContext(reader, "poll")
	ctx.Args = [6]uint64{0x2000, 3, 42}
	ctx.Opts = &cli.Options{StringLimit: 1, Verbose: true}
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  0,
			ProbeRet:  0,
			Data: append(append(
				makePollfdData(4, 1, 0),
				makePollfdData(5, 4, 0)...),
				makePollfdData(6, 4, 0)...),
		},
	}

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[0] != "[{fd=4, events=POLLIN}, {fd=5, events=POLLOUT}, {fd=6, events=POLLOUT}]" {
		t.Fatalf("poll fds = %q, want verbose full array", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPpollUsesPayloadSectionsForSigmaskAndLeftTimeout(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(99, 100)}
	ctx := newSelectPolicyContext(reader, "ppoll")
	ctx.Args = [6]uint64{0x2000, 2, 0x3000, 0x4000, 8}
	ctx.Ret = 1
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 0, ProbeRet: 0, Data: append(makePollfdData(4, 1, 0), makePollfdData(5, 4, 0)...)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: append(makePollfdData(4, 0, 0), makePollfdData(5, 0, 4)...)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 2, ProbeRet: 0, Data: makeSelectTime(9, 10)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: 0, Data: makeSelectTime(8, 7)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 3, ProbeRet: 0, Data: makePpollSigsetData((1 << 11) | (1 << 16))},
	}

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[1] != "2" || got.ArgParts[2] != "{tv_sec=9, tv_nsec=10}" ||
		got.ArgParts[3] != "[USR2 CHLD]" || got.ArgParts[4] != "8" {
		t.Fatalf("ppoll args = %+v", got.ArgParts)
	}
	if got.ReturnDesc != "[{fd=5, revents=POLLOUT}], left {tv_sec=8, tv_nsec=7}" {
		t.Fatalf("ReturnDesc = %q", got.ReturnDesc)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestPpollFormatsLow32BitNfdsAndRawSigsetSize(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSelectTime(99, 100)}
	ctx := newSelectPolicyContext(reader, "ppoll")
	ctx.Args = [6]uint64{0, 0xdeadbeeffacefeed, 0, 0, 0xdeadbeeffacefeed}

	got := (&PollHandler{}).Handle(ctx)
	if got.ArgParts[1] != "4207869677" {
		t.Fatalf("ppoll nfds = %q, want low 32-bit unsigned value", got.ArgParts[1])
	}
	if got.ArgParts[4] != "16045690985305276141" {
		t.Fatalf("ppoll sigsetsize = %q, want raw arg4", got.ArgParts[4])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
