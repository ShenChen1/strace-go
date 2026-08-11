package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestOpenTreeHandlerUsesSnapshotAndNarrowsFlags(t *testing.T) {
	ctx := mountPathTestContext(428)
	ctx.Args = [6]uint64{mountPathRawFD(AtFdcwd), 0x1000, 0xdefaced00080001}
	ctx.PayloadSections = []PayloadSection{mountPathStringSection(1, 0x1000, "tree")}

	got := (&OpenTreeHandler{}).Handle(ctx).ArgParts
	want := []string{`AT_FDCWD</tmp/base>`, `"tree"`, "OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC"}
	assertMountPathParts(t, got, want)
}

func TestMoveMountHandlerUsesBothSnapshotsAndNarrowsFlags(t *testing.T) {
	ctx := mountPathTestContext(429)
	ctx.Args = [6]uint64{4, 0x1000, 5, 0x2000, 0xdefaced00000377}
	ctx.FDStateView.(testFDStateView).paths["101:4"] = "/from"
	ctx.FDStateView.(testFDStateView).paths["101:5"] = "/to"
	ctx.PayloadSections = []PayloadSection{
		mountPathStringSection(1, 0x1000, "source"),
		mountPathStringSection(3, 0x2000, "target"),
	}

	got := (&MoveMountHandler{}).Handle(ctx).ArgParts
	want := []string{
		`4</from>`, `"source"`, `5</to>`, `"target"`,
		"MOVE_MOUNT_F_SYMLINKS|MOVE_MOUNT_F_AUTOMOUNTS|MOVE_MOUNT_F_EMPTY_PATH|" +
			"MOVE_MOUNT_T_SYMLINKS|MOVE_MOUNT_T_AUTOMOUNTS|MOVE_MOUNT_T_EMPTY_PATH|" +
			"MOVE_MOUNT_SET_GROUP|MOVE_MOUNT_BENEATH",
	}
	assertMountPathParts(t, got, want)
}

func TestMoveMountHandlerFallsBackToPointers(t *testing.T) {
	ctx := mountPathTestContext(429)
	ctx.Args = [6]uint64{mountPathRawFD(AtFdcwd), 0x1000, mountPathRawFD(AtFdcwd), 0x2000, 1}

	got := (&MoveMountHandler{}).Handle(ctx).ArgParts
	want := []string{`AT_FDCWD</tmp/base>`, "0x1000", `AT_FDCWD</tmp/base>`, "0x2000", "MOVE_MOUNT_F_SYMLINKS"}
	assertMountPathParts(t, got, want)
}

func mountPathTestContext(sysID uint32) *Context {
	return &Context{
		Pid: 101, Tid: 101, TargetPid: 101, SysId: sysID,
		SysName: meta.SyscallTable[sysID].Name, ScMeta: meta.SyscallTable[sysID],
		Decoder:     event.NewDecoder(),
		Opts:        &cli.Options{ShowPaths: true, ShowPathsMode: 1, XlatFormat: "abbrev", StringLimit: 32},
		FDStateView: testFDStateView{paths: map[string]string{"101:cwd": "/tmp/base"}},
	}
}

func mountPathStringSection(arg int, ptr uint64, value string) PayloadSection {
	data := append([]byte(value), 0)
	return PayloadSection{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: arg,
		UserPtr: ptr, UserLen: uint32(len(data)), CopiedLen: uint32(len(data)), ProbeRet: 0, Data: data}
}

func mountPathRawFD(fd int32) uint64 {
	return uint64(uint32(fd))
}

func assertMountPathParts(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("mount path arg count = %d, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mount path arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}
