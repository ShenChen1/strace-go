package handler

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func pselect6Wrapper(maskPtr uint64, size uint64) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], maskPtr)
	binary.LittleEndian.PutUint64(data[8:16], size)
	return data
}

func TestPselect6UsesTimespecAndEventTimeSigmaskSections(t *testing.T) {
	ctx := newSelectPolicyContext(nil, "pselect6")
	ctx.Args = [6]uint64{8, 0x1000, 0, 0, 0x3000, 0x5000}
	ctx.Ret = 1
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeFdSetData(3)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 4, ProbeRet: 0, Data: makeTimeStruct(9, 10)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 5, ProbeRet: 0, Data: pselect6Wrapper(0x6000, 8)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 6, ProbeRet: 0, Data: makeSigsetData(1)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeFdSetData(4)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 4, ProbeRet: 0, Data: makeTimeStruct(1, 2)},
	}

	got := (&SelectHandler{}).Handle(ctx)
	wantArgs := []string{
		"8",
		"[3]",
		"NULL",
		"NULL",
		"{tv_sec=9, tv_nsec=10}",
		"{sigmask=[HUP], sigsetsize=8}",
	}
	if !reflect.DeepEqual(got.ArgParts, wantArgs) {
		t.Fatalf("pselect6 args = %#v, want %#v", got.ArgParts, wantArgs)
	}
	if got.ReturnDesc != "in [4], left {tv_sec=1, tv_nsec=2}" {
		t.Fatalf("pselect6 return desc = %q", got.ReturnDesc)
	}
}

func TestPselect6FailureUsesEnterSnapshotWithoutOutput(t *testing.T) {
	ctx := newSelectPolicyContext(nil, "pselect6")
	ctx.Args = [6]uint64{8, 0x1000, 0, 0, 0x3000, 0x5000}
	ctx.Ret = -14
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeFdSetData(3)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 4, ProbeRet: 0, Data: makeTimeStruct(9, 10)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 5, ProbeRet: 0, Data: pselect6Wrapper(0x6000, 8)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 6, ProbeRet: 0, Data: makeSigsetData(1)},
	}

	got := (&SelectHandler{}).Handle(ctx)
	if len(got.ArgParts) != 6 || got.ArgParts[5] != "{sigmask=[HUP], sigsetsize=8}" {
		t.Fatalf("pselect6 failure args = %#v", got.ArgParts)
	}
	if got.ReturnDesc != "" || got.ShowEmptyReturnDesc {
		t.Fatalf("pselect6 failure return = %q/%v, want no output", got.ReturnDesc, got.ShowEmptyReturnDesc)
	}
}
