package handler

import (
	"strings"
	"testing"
)

func TestSendmmsgHandlerFormatsFourSlotsFromBoundedSnapshot(t *testing.T) {
	ctx := newMsgPolicyContext("sendmmsg")
	ctx.Ret = 4
	ctx.Args = [6]uint64{1, 0x1000, 4, 0}
	ctx.Opts.TraceWriteFDs = map[int32]bool{1: true}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 1, 0, 0, 0, 0),
			mmsghdrBytes(0, 0, 0x3000, 1, 0, 0, 0, 0),
			mmsghdrBytes(0, 0, 0x4000, 1, 0, 0, 0, 0),
			mmsghdrBytes(0, 0, 0x5000, 1, 0, 0, 0, 0),
		)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 1, 0, 0, 0, 1),
			mmsghdrBytes(0, 0, 0x3000, 1, 0, 0, 0, 2),
			mmsghdrBytes(0, 0, 0x4000, 1, 0, 0, 0, 3),
			mmsghdrBytes(0, 0, 0x5000, 1, 0, 0, 0, 4),
		)},
	}
	for slot, value := range []struct {
		arg  int
		base uint64
		text string
	}{
		{arg: 1, base: 0x2000, text: "A"},
		{arg: 151, base: 0x3000, text: "B"},
		{arg: 181, base: 0x4000, text: "C"},
		{arg: 211, base: 0x5000, text: "D"},
	} {
		ctx.PayloadSections = append(ctx.PayloadSections,
			PayloadSection{
				Kind:      PayloadKindIovec,
				Direction: PayloadDirectionIn,
				ArgIndex:  value.arg,
				UserPtr:   value.base,
				Data:      iovecBytes([2]uint64{value.base + 0x1000, 1}),
			},
			PayloadSection{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionIn,
				ArgIndex:  mmsgTestPayloadArg(slot),
				UserPtr:   value.base + 0x1000,
				Data:      []byte(value.text),
			},
		)
	}

	res := (&MsgHandler{}).Handle(ctx)
	if len(res.ArgParts) < 2 {
		t.Fatalf("sendmmsg arg parts = %+v, want fd and four-slot vector", res.ArgParts)
	}
	for _, marker := range []string{"msg_len=1", "msg_len=2", "msg_len=3", "msg_len=4", "iov_base=\"C\"", "iov_base=\"D\""} {
		if !strings.Contains(res.ArgParts[1], marker) {
			t.Fatalf("sendmmsg vector missing %q: %s", marker, res.ArgParts[1])
		}
	}
}

func mmsgTestPayloadArg(slot int) int {
	switch slot {
	case 0:
		return 120
	case 1:
		return 160
	case 2:
		return 180
	default:
		return 200
	}
}
