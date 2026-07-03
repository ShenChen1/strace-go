package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
)

func makeBtrfsWaitSyncData(v uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, v)
	return data
}

func makeBtrfsVolArgs(fd int64, name string) []byte {
	data := make([]byte, 4096)
	binary.LittleEndian.PutUint64(data[0:8], uint64(fd))
	copy(data[8:], []byte(name))
	return data
}

func makeBtrfsVolArgsV2(fd int64, flags, size, qgroup uint64, name string) []byte {
	data := make([]byte, 4096)
	binary.LittleEndian.PutUint64(data[0:8], uint64(fd))
	binary.LittleEndian.PutUint64(data[16:24], flags)
	binary.LittleEndian.PutUint64(data[24:32], size)
	binary.LittleEndian.PutUint64(data[32:40], qgroup)
	copy(data[56:], []byte(name))
	return data
}

func makeBtrfsQgroupInheritData() ([]byte, []byte) {
	data := make([]byte, 64)
	tail := make([]byte, 8)
	binary.LittleEndian.PutUint64(data[0:8], 2)
	binary.LittleEndian.PutUint64(data[8:16], 3)
	binary.LittleEndian.PutUint64(data[16:24], 4)
	binary.LittleEndian.PutUint64(data[24:32], 5)
	binary.LittleEndian.PutUint64(data[32:40], 1|8)
	binary.LittleEndian.PutUint64(data[40:48], 10)
	binary.LittleEndian.PutUint64(data[48:56], 11)
	binary.LittleEndian.PutUint64(data[56:64], 12)
	binary.LittleEndian.PutUint64(tail, 13)
	return data, tail
}

func TestBtrfsWaitSyncDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBtrfsWaitSyncData(42),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)

	got := (&IoctlHandler{}).decodeBtrfsWaitSync(ctx, 0x1000)
	if got != "0x1000" {
		t.Fatalf("decodeBtrfsWaitSync() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBtrfsWaitSyncIgnoresLegacySnapshot(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x1000: makeBtrfsWaitSyncData(42),
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())
	ctx.ProbeRetEnter = 0
	copy(ctx.StrArgBuf[512:520], makeBtrfsWaitSyncData(42))
	ctx.DataLen = 520

	got := (&IoctlHandler{}).decodeBtrfsWaitSync(ctx, 0x1000)
	if got != "0x1000" {
		t.Fatalf("decodeBtrfsWaitSync() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBtrfsWaitSyncUsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x1000, ProbeRet: 0, Data: makeBtrfsWaitSyncData(42)},
	}

	got := (&IoctlHandler{}).decodeBtrfsWaitSync(ctx, 0x1000)
	if got != "[42]" {
		t.Fatalf("decodeBtrfsWaitSync() = %q", got)
	}
}

func TestBtrfsVolArgsIgnoresLegacySnapshot(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x2000: makeBtrfsVolArgs(9, "ignored"),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)
	ctx.ProbeRetEnter = 0
	copy(ctx.StrArgBuf[512:], makeBtrfsVolArgs(7, "snap"))
	ctx.DataLen = uint32(512 + len(makeBtrfsVolArgs(7, "snap")))

	got := (&IoctlHandler{}).decodeBtrfsVolArgs(ctx, 0x2000)
	if got != "0x2000" {
		t.Fatalf("decodeBtrfsVolArgs() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBtrfsVolArgsUsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x2000, ProbeRet: 0, Data: makeBtrfsVolArgs(7, "snap")},
	}

	got := (&IoctlHandler{}).decodeBtrfsVolArgs(ctx, 0x2000)
	if !strings.Contains(got, "fd=7") || !strings.Contains(got, `name="snap"`) {
		t.Fatalf("decodeBtrfsVolArgs() = %q", got)
	}
}

func TestBtrfsVolArgsDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x2000: makeBtrfsVolArgs(7, "snap"),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)

	got := (&IoctlHandler{}).decodeBtrfsVolArgs(ctx, 0x2000)
	if got != "0x2000" {
		t.Fatalf("decodeBtrfsVolArgs() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBtrfsVolArgsDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x2000: makeBtrfsVolArgs(7, "snap"),
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())

	got := (&IoctlHandler{}).decodeBtrfsVolArgs(ctx, 0x2000)
	if got != "0x2000" {
		t.Fatalf("decodeBtrfsVolArgs() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBtrfsVolArgsV2DoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: makeBtrfsVolArgsV2(8, 2, 4096, 0, "subvol"),
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)

	got := (&IoctlHandler{}).decodeBtrfsVolArgsV2(ctx, 0x3000)
	if got != "0x3000" {
		t.Fatalf("decodeBtrfsVolArgsV2() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBtrfsVolArgsV2IgnoresLegacySnapshot(t *testing.T) {
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x3000: makeBtrfsVolArgsV2(8, 2, 4096, 0, "subvol"),
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())
	snap := makeBtrfsVolArgsV2(8, 2, 4096, 0, "subvol")
	ctx.ProbeRetEnter = 0
	copy(ctx.StrArgBuf[512:], snap)
	ctx.DataLen = uint32(512 + len(snap))

	got := (&IoctlHandler{}).decodeBtrfsVolArgsV2(ctx, 0x3000)
	if got != "0x3000" {
		t.Fatalf("decodeBtrfsVolArgsV2() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBtrfsVolArgsV2UsesPayloadBytesSection(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.StrArgBuf = nil
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: makeBtrfsVolArgsV2(8, 2, 4096, 0, "subvol")},
	}

	got := (&IoctlHandler{}).decodeBtrfsVolArgsV2(ctx, 0x3000)
	if !strings.Contains(got, "fd=8") || !strings.Contains(got, "flags=BTRFS_SUBVOL_RDONLY") || !strings.Contains(got, `name="subvol"`) {
		t.Fatalf("decodeBtrfsVolArgsV2() = %q", got)
	}
}

func TestBtrfsQgroupInheritDoesNotReadWhenFallbackDisabled(t *testing.T) {
	qgroup, tail := makeBtrfsQgroupInheritData()
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: qgroup,
		0x4040: tail,
	}}
	decoder := event.NewDecoder()
	ctx := newIoctlPolicyContext(reader, decoder)

	got := (&IoctlHandler{}).decodeBtrfsQgroupInherit(ctx, 0x4000)
	if got != "0x4000" {
		t.Fatalf("decodeBtrfsQgroupInherit() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestBtrfsQgroupInheritDoesNotUseLegacyMemoryFallback(t *testing.T) {
	qgroup, tail := makeBtrfsQgroupInheritData()
	reader := &ioctlPolicyMemoryReader{data: map[uint64][]byte{
		0x4000: qgroup,
		0x4040: tail,
	}}
	ctx := newIoctlPolicyContext(reader, event.NewDecoder())

	got := (&IoctlHandler{}).decodeBtrfsQgroupInherit(ctx, 0x4000)
	if got != "0x4000" {
		t.Fatalf("decodeBtrfsQgroupInherit() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
