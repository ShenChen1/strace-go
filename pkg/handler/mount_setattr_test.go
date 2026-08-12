package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestMountSetattrHandlerFormatsProbeSitePayload(t *testing.T) {
	ctx := mountSetattrTestContext(40)
	ctx.PayloadSections = []PayloadSection{
		mountSetattrTestSection(PayloadKindString, 1, []byte("/dev/full\x00"), 0),
		mountSetattrTestSection(PayloadKindStruct, 3, mountSetattrTestBase(), 0),
		mountSetattrTestSection(PayloadKindBytes, 3, []byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87}, 0),
	}

	got := (&MountSetattrHandler{}).Handle(ctx).ArgParts
	want := []string{
		"AT_FDCWD",
		`"/dev/full"`,
		"AT_EMPTY_PATH",
		`{attr_set=MOUNT_ATTR_NOSUID|MOUNT_ATTR_IDMAP, attr_clr=MOUNT_ATTR_NODEV, propagation=MS_SLAVE, userns_fd=9, /* bytes 32..39 */ "\x80\x81\x82\x83\x84\x85\x86\x87"}`,
		"40",
	}
	assertMountSetattrParts(t, got, want)
}

func TestMountSetattrHandlerPreservesBaseWhenExtensionFaults(t *testing.T) {
	ctx := mountSetattrTestContext(40)
	ctx.PayloadSections = []PayloadSection{
		mountSetattrTestSection(PayloadKindString, 1, []byte("/dev/full\x00"), 0),
		mountSetattrTestSection(PayloadKindStruct, 3, mountSetattrTestBase(), 0),
		mountSetattrTestSection(PayloadKindBytes, 3, nil, -14),
	}

	got := (&MountSetattrHandler{}).Handle(ctx).ArgParts[3]
	want := "{attr_set=MOUNT_ATTR_NOSUID|MOUNT_ATTR_IDMAP, attr_clr=MOUNT_ATTR_NODEV, propagation=MS_SLAVE, userns_fd=9, ???}"
	if got != want {
		t.Fatalf("mount_setattr extension fault = %q, want %q", got, want)
	}
}

func TestMountSetattrHandlerUsesPointerBelowVersionZeroSize(t *testing.T) {
	ctx := mountSetattrTestContext(31)
	ctx.PayloadSections = []PayloadSection{
		mountSetattrTestSection(PayloadKindString, 1, []byte("/dev/full\x00"), 0),
	}

	got := (&MountSetattrHandler{}).Handle(ctx).ArgParts[3]
	if got != "0x2000" {
		t.Fatalf("mount_setattr short attr = %q, want pointer", got)
	}
}

func TestMountSetattrHandlerPreservesTrailingZeroExtensionBytes(t *testing.T) {
	ctx := mountSetattrTestContext(35)
	ctx.PayloadSections = []PayloadSection{
		mountSetattrTestSection(PayloadKindString, 1, []byte("/dev/full\x00"), 0),
		mountSetattrTestSection(PayloadKindStruct, 3, mountSetattrTestBase(), 0),
		mountSetattrTestSection(PayloadKindBytes, 3, []byte{0x80, 0, 0}, 0),
	}

	got := (&MountSetattrHandler{}).Handle(ctx).ArgParts[3]
	wantSuffix := `, /* bytes 32..34 */ "\x80\x00\x00"}`
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("mount_setattr trailing zeros = %q, want suffix %q", got, wantSuffix)
	}
}

func TestMountSetattrHandlerPreserves64BitPropagation(t *testing.T) {
	ctx := mountSetattrTestContext(32)
	base := mountSetattrTestBase()
	binary.LittleEndian.PutUint64(base[16:24], 0x100000000)
	ctx.PayloadSections = []PayloadSection{
		mountSetattrTestSection(PayloadKindString, 1, []byte("/dev/full\x00"), 0),
		mountSetattrTestSection(PayloadKindStruct, 3, base, 0),
	}

	got := (&MountSetattrHandler{}).Handle(ctx).ArgParts[3]
	if !strings.Contains(got, "propagation=0x100000000 /* MS_??? */") {
		t.Fatalf("mount_setattr propagation = %q, want full-width unknown value", got)
	}
}

func mountSetattrTestContext(size uint64) *Context {
	dfd := int32(AtFdcwd)
	return &Context{
		Pid:       1234,
		Tid:       1234,
		TargetPid: 1234,
		SysId:     442,
		SysName:   "mount_setattr",
		Args:      [6]uint64{uint64(uint32(dfd)), 0x1000, 0x1000, 0x2000, size},
		Ret:       -22,
		ScMeta:    meta.SyscallTable[442],
		Decoder:   event.NewDecoder(),
		Meta:      meta.NewCatalog("abbrev"),
		Opts:      &cli.Options{StringLimit: 32, XlatFormat: "abbrev"},
	}
}

func mountSetattrTestBase() []byte {
	data := make([]byte, mountSetattrBaseSize)
	binary.LittleEndian.PutUint64(data[0:8], 0x100002)
	binary.LittleEndian.PutUint64(data[8:16], 0x4)
	binary.LittleEndian.PutUint64(data[16:24], 0x80000)
	binary.LittleEndian.PutUint64(data[24:32], 9)
	return data
}

func mountSetattrTestSection(kind PayloadKind, argIndex int, data []byte, probeRet int32) PayloadSection {
	return PayloadSection{
		Kind:      kind,
		Direction: PayloadDirectionIn,
		ArgIndex:  argIndex,
		UserPtr:   0x2000,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		ProbeRet:  probeRet,
		Data:      data,
	}
}

func assertMountSetattrParts(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("mount_setattr arg count = %d, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mount_setattr arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}
