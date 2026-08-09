package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestStatmountHandlerFormatsVersionedRequestAndFlags(t *testing.T) {
	ctx := mountQueryTestContext(457, "statmount")
	ctx.Args = [6]uint64{0x1000, 0, 0, 1}
	ctx.PayloadSections = mntIDRequestTestSections(40, 0, 0x1234, 0x8001, 0x5678)
	ctx.PayloadSections = append(ctx.PayloadSections, mountQuerySection(mountQuerySectionSpec{
		kind: PayloadKindBytes, direction: PayloadDirectionIn, arg: 0, ptr: 0x1020,
		data: []byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87}, userLen: 8,
	}))

	got := (&StatmountHandler{}).Handle(ctx).ArgParts
	want := []string{
		`{size=40, mnt_ns_fd=0, mnt_id=0x1234, param=STATMOUNT_SB_BASIC|0x8000, mnt_ns_id=0x5678, /* bytes 32..39 */ "\x80\x81\x82\x83\x84\x85\x86\x87"}`,
		"NULL", "0", "STATMOUNT_BY_FD",
	}
	assertMountQueryParts(t, got, want)
}

func TestListmountHandlerUsesSharedRequestWithListSemantics(t *testing.T) {
	ctx := mountQueryTestContext(458, "listmount")
	ctx.Args = [6]uint64{0x1000, 0, 0, 1}
	ctx.PayloadSections = mntIDRequestTestSections(32, -1, ^uint64(0), 0x99, 0x5678)

	got := (&ListmountHandler{}).Handle(ctx).ArgParts
	want := []string{
		"{size=32, mnt_ns_fd=-1, mnt_id=LSMT_ROOT, param=0x99, mnt_ns_id=0x5678}",
		"NULL", "0", "LISTMOUNT_REVERSE",
	}
	assertMountQueryParts(t, got, want)
}

func TestMountQueryRequestPreservesSizeWhenBaseFaults(t *testing.T) {
	ctx := mountQueryTestContext(457, "statmount")
	ctx.Args[0] = 0x1000
	ctx.PayloadSections = []PayloadSection{
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionIn, arg: 0, ptr: 0x1000, data: u32Bytes(24), userLen: 4}),
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionIn, arg: 0, ptr: 0x1000, userLen: 24, probeRet: -14}),
	}

	got := (&StatmountHandler{}).Handle(ctx).ArgParts[0]
	if got != "{size=24, ???}" {
		t.Fatalf("statmount partial request = %q, want size plus unavailable marker", got)
	}
}

func TestListmountHandlerFormatsCapturedOutputPrefix(t *testing.T) {
	ctx := mountQueryTestContext(458, "listmount")
	ctx.Args = [6]uint64{0, 0x2000, 3, 0}
	ctx.Ret = 3
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], 0x11)
	binary.LittleEndian.PutUint64(data[8:16], 0x22)
	ctx.PayloadSections = []PayloadSection{
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindBytes, direction: PayloadDirectionOut, arg: 1, ptr: 0x2000, data: data, userLen: 24, probeRet: -14}),
	}

	got := (&ListmountHandler{}).Handle(ctx).ArgParts[1]
	want := "[0x11, 0x22, ... /* 0x2010 */]"
	if got != want {
		t.Fatalf("listmount output = %q, want %q", got, want)
	}
}

func TestStatmountHandlerFormatsCapturedOutput(t *testing.T) {
	ctx := mountQueryTestContext(457, "statmount")
	ctx.Args = [6]uint64{0, 0x3000, 520, 0}
	ctx.Ret = 0
	base := make([]byte, statmountFixedSize)
	binary.LittleEndian.PutUint32(base[0:4], 520)
	binary.LittleEndian.PutUint64(base[8:16], statmountMaskSB|statmountMaskFS)
	binary.LittleEndian.PutUint32(base[16:20], 8)
	binary.LittleEndian.PutUint32(base[20:24], 1)
	binary.LittleEndian.PutUint64(base[24:32], 0x9fa0)
	binary.LittleEndian.PutUint32(base[32:36], 1)
	binary.LittleEndian.PutUint32(base[36:40], 0)
	ctx.PayloadSections = []PayloadSection{
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionOut, arg: 1, ptr: 0x3000, data: u32Bytes(520), userLen: 4}),
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionOut, arg: 1, ptr: 0x3000, data: base, userLen: statmountFixedSize}),
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindBytes, direction: PayloadDirectionOut, arg: 1, ptr: 0x3200, data: []byte("ext4\x00\x00\x00\x00"), userLen: 8}),
	}

	got := (&StatmountHandler{}).Handle(ctx).ArgParts[1]
	want := "{size=520, mask=STATMOUNT_SB_BASIC|STATMOUNT_FS_TYPE, sb_dev_major=8, sb_dev_minor=1, sb_magic=PROC_SUPER_MAGIC, sb_flags=MS_RDONLY, fs_type=\"ext4\"}"
	if got != want {
		t.Fatalf("statmount output = %q, want %q", got, want)
	}
}

func TestStatmountHandlerPreservesUpstreamFieldOrder(t *testing.T) {
	ctx := mountQueryTestContext(457, "statmount")
	ctx.Args = [6]uint64{0, 0x3000, 525, 0}
	ctx.Ret = 0
	base := make([]byte, statmountFixedSize)
	mask := statmountMaskMount | statmountMaskFS | statmountMaskNS |
		statmountMaskSub | statmountMaskSource
	binary.LittleEndian.PutUint32(base[0:4], 525)
	binary.LittleEndian.PutUint64(base[8:16], mask)
	binary.LittleEndian.PutUint32(base[36:40], 0)
	binary.LittleEndian.PutUint64(base[40:48], 0x11)
	binary.LittleEndian.PutUint64(base[48:56], 0x22)
	binary.LittleEndian.PutUint32(base[56:60], 0x33)
	binary.LittleEndian.PutUint32(base[60:64], 0x44)
	binary.LittleEndian.PutUint64(base[80:88], 0x55)
	binary.LittleEndian.PutUint64(base[88:96], 0x66)
	binary.LittleEndian.PutUint64(base[112:120], 0x77)
	binary.LittleEndian.PutUint32(base[120:124], 5)
	binary.LittleEndian.PutUint32(base[124:128], 9)
	ctx.PayloadSections = []PayloadSection{
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionOut, arg: 1, ptr: 0x3000, data: u32Bytes(525), userLen: 4}),
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionOut, arg: 1, ptr: 0x3000, data: base, userLen: statmountFixedSize}),
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindBytes, direction: PayloadDirectionOut, arg: 1, ptr: 0x3200, data: []byte("ext4\x00sub\x00src\x00"), userLen: 13}),
	}

	got := (&StatmountHandler{}).Handle(ctx).ArgParts[1]
	want := "{size=525, mask=STATMOUNT_MNT_BASIC|STATMOUNT_FS_TYPE|STATMOUNT_MNT_NS_ID|STATMOUNT_FS_SUBTYPE|STATMOUNT_SB_SOURCE, " +
		"fs_type=\"ext4\", mnt_id=0x11, mnt_parent_id=0x22, mnt_id_old=0x33, mnt_parent_id_old=0x44, " +
		"mnt_attr=0, mnt_propagation=0, mnt_peer_group=0x55, mnt_master=0x66, mnt_ns_id=0x77, " +
		"fs_subtype=\"sub\", sb_source=\"src\"}"
	if got != want {
		t.Fatalf("statmount output = %q, want %q", got, want)
	}
}

func TestStatmountHandlerAppliesStringLimit(t *testing.T) {
	ctx := mountQueryTestContext(457, "statmount")
	ctx.Args = [6]uint64{0, 0x3000, 529, 0}
	ctx.Ret = 0
	ctx.Opts.StringLimit = 4
	base := make([]byte, statmountFixedSize)
	binary.LittleEndian.PutUint32(base[0:4], 529)
	binary.LittleEndian.PutUint64(base[8:16], statmountMaskFS)
	ctx.PayloadSections = []PayloadSection{
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionOut, arg: 1, ptr: 0x3000, data: u32Bytes(529), userLen: 4}),
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionOut, arg: 1, ptr: 0x3000, data: base, userLen: statmountFixedSize}),
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindBytes, direction: PayloadDirectionOut, arg: 1, ptr: 0x3200, data: []byte("long-filesystem\x00"), userLen: 17}),
	}

	got := (&StatmountHandler{}).Handle(ctx).ArgParts[1]
	want := `{size=529, mask=STATMOUNT_FS_TYPE, fs_type="long"...}`
	if got != want {
		t.Fatalf("statmount output = %q, want %q", got, want)
	}
}

func mountQueryTestContext(sysID uint32, name string) *Context {
	return &Context{
		Pid: 1234, Tid: 1234, TargetPid: 1234, SysId: sysID, SysName: name,
		Ret: -22, ScMeta: meta.SyscallTable[sysID], Decoder: event.NewDecoder(),
		Opts: &cli.Options{StringLimit: 32, XlatFormat: "abbrev"},
	}
}

func mntIDRequestTestSections(size uint32, fd int32, mountID, param, namespaceID uint64) []PayloadSection {
	base := make([]byte, mntIDRequestVersionOneSize)
	binary.LittleEndian.PutUint32(base[0:4], size)
	binary.LittleEndian.PutUint32(base[4:8], uint32(fd))
	binary.LittleEndian.PutUint64(base[8:16], mountID)
	binary.LittleEndian.PutUint64(base[16:24], param)
	binary.LittleEndian.PutUint64(base[24:32], namespaceID)
	return []PayloadSection{
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionIn, arg: 0, ptr: 0x1000, data: base[:4], userLen: 4}),
		mountQuerySection(mountQuerySectionSpec{kind: PayloadKindStruct, direction: PayloadDirectionIn, arg: 0, ptr: 0x1000, data: base, userLen: uint32(len(base))}),
	}
}

type mountQuerySectionSpec struct {
	kind      PayloadKind
	direction PayloadDirection
	arg       int
	ptr       uint64
	data      []byte
	userLen   uint32
	probeRet  int32
}

func mountQuerySection(spec mountQuerySectionSpec) PayloadSection {
	return PayloadSection{Kind: spec.kind, Direction: spec.direction, ArgIndex: spec.arg,
		UserPtr: spec.ptr, UserLen: spec.userLen, CopiedLen: uint32(len(spec.data)),
		ProbeRet: spec.probeRet, Data: spec.data}
}

func u32Bytes(value uint32) []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, value)
	return data
}

func assertMountQueryParts(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("mount query arg count = %d, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mount query arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}
