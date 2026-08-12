package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestStatxHandlerFormatsProbeSitePayload(t *testing.T) {
	ctx := statxTestContext(0)
	ctx.PayloadSections = []PayloadSection{
		statxTestSection(PayloadKindString, PayloadDirectionIn, 1, []byte("stat.sample\x00")),
		statxTestSection(PayloadKindStruct, PayloadDirectionOut, 4, statxTestStruct()),
	}

	got := (&StatxHandler{}).Handle(ctx).ArgParts
	want := []string{
		"AT_FDCWD",
		`"stat.sample"`,
		"AT_STATX_SYNC_AS_STAT",
		"STATX_TYPE|STATX_MODE|STATX_UID|STATX_ATIME|STATX_MNT_ID",
		"{stx_mask=STATX_TYPE|STATX_MODE|STATX_UID|STATX_ATIME|STATX_MNT_ID, stx_blksize=4096, stx_attributes=0, stx_uid=1000, stx_mode=S_IFREG|0640, stx_attributes_mask=STATX_ATTR_IMMUTABLE|STATX_ATTR_DAX, stx_atime={tv_sec=-10843, tv_nsec=135} /* 1969-12-31T20:59:17.000000135+0000 */, stx_rdev_major=0, stx_rdev_minor=0, stx_dev_major=0, stx_dev_minor=37, stx_mnt_id=0x41}",
	}
	assertStatxParts(t, got, want)
}

func TestStatxHandlerFallsBackToPointerAfterFailedSyscall(t *testing.T) {
	ctx := statxTestContext(-14)
	ctx.PayloadSections = []PayloadSection{
		statxTestSection(PayloadKindString, PayloadDirectionIn, 1, []byte("stat.sample\x00")),
	}

	got := (&StatxHandler{}).Handle(ctx).ArgParts
	want := []string{
		"AT_FDCWD",
		`"stat.sample"`,
		"AT_STATX_SYNC_AS_STAT",
		"STATX_TYPE|STATX_MODE|STATX_UID|STATX_ATIME|STATX_MNT_ID",
		"0x2000",
	}
	assertStatxParts(t, got, want)
}

func TestStatxSnapshotAbbreviatesAfterStableFields(t *testing.T) {
	data := make([]byte, statxStructSize)
	binary.LittleEndian.PutUint32(data[0:4], statxMode|statxSize)
	binary.LittleEndian.PutUint64(data[8:16], 0x10)
	binary.LittleEndian.PutUint16(data[28:30], 0100640)
	binary.LittleEndian.PutUint64(data[40:48], 42)

	got := parseStatxSnapshot(data).format(statxTestContext(0), false)
	want := "{stx_mask=STATX_MODE|STATX_SIZE, stx_attributes=STATX_ATTR_IMMUTABLE, stx_mode=S_IFREG|0640, stx_size=42, ...}"
	if got != want {
		t.Fatalf("abbreviated statx = %q, want %q", got, want)
	}
}

func TestStatxSnapshotUsesAttributesForAtomicWriteFields(t *testing.T) {
	data := make([]byte, statxStructSize)
	binary.LittleEndian.PutUint32(data[0:4], statxDioReadAlign)
	binary.LittleEndian.PutUint64(data[8:16], 0x400000)
	binary.LittleEndian.PutUint32(data[168:172], 1)
	binary.LittleEndian.PutUint32(data[172:176], 2)
	binary.LittleEndian.PutUint32(data[176:180], 3)
	binary.LittleEndian.PutUint32(data[180:184], 4)
	binary.LittleEndian.PutUint32(data[184:188], 5)

	got := parseStatxSnapshot(data).format(statxTestContext(0), true)
	wantSuffix := "stx_atomic_write_unit_min=1, stx_atomic_write_unit_max=2, stx_atomic_write_segments_max=3, stx_dio_read_offset_align=4, stx_atomic_write_unit_max_opt=5}"
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("atomic statx = %q, want suffix %q", got, wantSuffix)
	}
}

func statxTestContext(ret int64) *Context {
	dfd := int32(AtFdcwd)
	return &Context{
		Pid:       1234,
		Tid:       1234,
		SysId:     332,
		SysName:   "statx",
		Args:      [6]uint64{uint64(uint32(dfd)), 0x1000, 0, 0x102b, 0x2000},
		Ret:       ret,
		ScMeta:    meta.SyscallTable[332],
		Decoder:   event.NewDecoder(),
		Opts:      &cli.Options{StringLimit: 32, XlatFormat: "abbrev", Verbose: true},
		Meta:      meta.NewCatalog("abbrev"),
		Registry:  NewRegistry(),
		TargetPid: 1234,
	}
}

func statxTestSection(kind PayloadKind, direction PayloadDirection, argIndex int, data []byte) PayloadSection {
	return PayloadSection{
		Kind:      kind,
		Direction: direction,
		ArgIndex:  argIndex,
		UserPtr:   []uint64{0, 0x1000, 0, 0, 0x2000}[argIndex],
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		Data:      data,
	}
}

func statxTestStruct() []byte {
	data := make([]byte, statxStructSize)
	atimeSec := int64(-10843)
	binary.LittleEndian.PutUint32(data[0:4], 0x102b)
	binary.LittleEndian.PutUint32(data[4:8], 4096)
	binary.LittleEndian.PutUint32(data[20:24], 1000)
	binary.LittleEndian.PutUint16(data[28:30], 0100640)
	binary.LittleEndian.PutUint64(data[56:64], 0x200010)
	binary.LittleEndian.PutUint64(data[64:72], uint64(atimeSec))
	binary.LittleEndian.PutUint32(data[72:76], 135)
	binary.LittleEndian.PutUint32(data[140:144], 37)
	binary.LittleEndian.PutUint64(data[144:152], 0x41)
	return data
}

func assertStatxParts(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("statx arg count = %d, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("statx arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}
