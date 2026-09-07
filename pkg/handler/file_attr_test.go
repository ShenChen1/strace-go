package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

const testFileAttrBaseSize = 24

func TestFileAttrHandlerFormatsSetInputAndExtension(t *testing.T) {
	data := fileAttrTestData(0x8003fffb, 0xdeadbeef, 0xcafef00d, 0xbabec0de)
	ctx := fileAttrTestContext("file_setattr", 32)
	ctx.PayloadSections = []PayloadSection{
		fileAttrTestSection(PayloadKindStruct, PayloadDirectionIn, 2, 0x2000, data),
		fileAttrTestSection(PayloadKindBytes, PayloadDirectionIn, 2, 0x2018, []byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87}),
	}

	got := NewRegistry().Default().Handle(ctx).ArgParts[2]
	want := "{fa_xflags=FS_XFLAG_REALTIME|FS_XFLAG_PREALLOC|FS_XFLAG_IMMUTABLE|FS_XFLAG_APPEND|FS_XFLAG_SYNC|FS_XFLAG_NOATIME|FS_XFLAG_NODUMP|FS_XFLAG_RTINHERIT|FS_XFLAG_PROJINHERIT|FS_XFLAG_NOSYMLINKS|FS_XFLAG_EXTSIZE|FS_XFLAG_EXTSZINHERIT|FS_XFLAG_NODEFRAG|FS_XFLAG_FILESTREAM|FS_XFLAG_DAX|FS_XFLAG_COWEXTSIZE|FS_XFLAG_VERITY|FS_XFLAG_HASATTR, fa_extsize=3735928559, fa_projid=0xcafef00d, fa_cowextsize=3133063390, /* bytes 24..31 */ \"\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\"}"
	if got != want {
		t.Fatalf("file_setattr attr = %q, want %q", got, want)
	}
}

func TestFileAttrHandlerFormatsGetOutput(t *testing.T) {
	data := fileAttrTestData(0, 17, 0x2a, 19)
	ctx := fileAttrTestContext("file_getattr", 24)
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		fileAttrTestSection(PayloadKindStruct, PayloadDirectionOut, 2, 0x2000, data),
	}

	got := NewRegistry().Default().Handle(ctx).ArgParts[2]
	if want := "{fa_xflags=0, fa_extsize=17, fa_nextents=0, fa_projid=0x2a, fa_cowextsize=19}"; got != want {
		t.Fatalf("file_getattr attr = %q, want %q", got, want)
	}
}

func TestFileAttrHandlerFormatsZeroProjectIDAsDecimal(t *testing.T) {
	ctx := fileAttrTestContext("file_setattr", 24)
	ctx.PayloadSections = []PayloadSection{
		fileAttrTestSection(PayloadKindStruct, PayloadDirectionIn, 2, 0x2000, fileAttrTestData(0, 0, 0, 0)),
	}

	got := NewRegistry().Default().Handle(ctx).ArgParts[2]
	if want := "{fa_xflags=0, fa_extsize=0, fa_projid=0, fa_cowextsize=0}"; got != want {
		t.Fatalf("zero file_setattr attr = %q, want %q", got, want)
	}
}

func TestFileAttrHandlerFallsBackWithoutCompleteSnapshot(t *testing.T) {
	ctx := fileAttrTestContext("file_setattr", 24)
	ctx.PayloadSections = []PayloadSection{
		fileAttrTestSection(PayloadKindStruct, PayloadDirectionIn, 2, 0x2000, make([]byte, testFileAttrBaseSize-1)),
	}

	got := NewRegistry().Default().Handle(ctx).ArgParts[2]
	if want := "0x2000"; got != want {
		t.Fatalf("file_setattr incomplete attr = %q, want %q", got, want)
	}
}

func fileAttrTestContext(name string, size uint64) *Context {
	dfd := int64(AtFdcwd)
	return &Context{
		Pid:       1234,
		Tid:       1234,
		TargetPid: 1234,
		SysId:     468,
		SysName:   name,
		Args:      [6]uint64{uint64(dfd), 0x1000, 0x2000, size, 0},
		Ret:       -2,
		ScMeta:    meta.SyscallTable[468],
		Decoder:   event.NewDecoder(),
		Meta:      meta.NewCatalog("abbrev"),
		Registry:  NewRegistry(),
		Opts:      &cli.Options{StringLimit: 32, XlatFormat: "abbrev"},
	}
}

func fileAttrTestData(xflags uint64, extsize, projid, cowextsize uint32) []byte {
	data := make([]byte, testFileAttrBaseSize)
	binary.LittleEndian.PutUint64(data[0:8], xflags)
	binary.LittleEndian.PutUint32(data[8:12], extsize)
	binary.LittleEndian.PutUint32(data[12:16], 0)
	binary.LittleEndian.PutUint32(data[16:20], projid)
	binary.LittleEndian.PutUint32(data[20:24], cowextsize)
	return data
}

func fileAttrTestSection(kind PayloadKind, direction PayloadDirection, arg int, ptr uint64, data []byte) PayloadSection {
	return PayloadSection{
		Kind:      kind,
		Direction: direction,
		ArgIndex:  arg,
		UserPtr:   ptr,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}
}
