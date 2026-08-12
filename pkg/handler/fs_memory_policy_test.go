package handler

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func newFsconfigBinaryContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "fsconfig",
		Args:          [6]uint64{3, 2, 0x1000, 0x2000, 3},
		ProbeRetEnter: 0,
		Decoder:       decoder,
		Meta:          meta.NewCatalog("abbrev"),
		Opts:          &cli.Options{StringLimit: 32},
	}
}

func TestFsconfigBinaryDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: []byte{1, 2, 3}}
	decoder := event.NewDecoder()
	ctx := newFsconfigBinaryContext(reader, decoder)

	got := (&FsHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 {
		t.Fatalf("ArgParts len = %d, want 5", len(got.ArgParts))
	}
	if got.ArgParts[3] != "0x2000" {
		t.Fatalf("fsconfig value = %q, want pointer fallback", got.ArgParts[3])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFsconfigBinaryIgnoresLegacyEnterSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: []byte{1, 2, 3}}
	ctx := newFsconfigBinaryContext(reader, event.NewDecoder())

	got := (&FsHandler{}).Handle(ctx)
	if len(got.ArgParts) != 5 {
		t.Fatalf("ArgParts len = %d, want 5", len(got.ArgParts))
	}
	if got.ArgParts[2] != "0x1000" || got.ArgParts[3] != "0x2000" {
		t.Fatalf("fsconfig args = %#v, want pointer fallbacks", got.ArgParts)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFsconfigStringUsesPayloadStringSections(t *testing.T) {
	ctx := newFsconfigBinaryContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.Args = [6]uint64{3, 1, 0x1000, 0x2000, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("key\x00")},
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 3, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("value\x00")},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[2] != `"key"` || got.ArgParts[3] != `"value"` {
		t.Fatalf("fsconfig string args = %#v", got.ArgParts)
	}
}

func TestFsconfigStringMarksSectionAtDisplayLimitTruncated(t *testing.T) {
	ctx := newFsconfigBinaryContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.Args = [6]uint64{3, 1, 0x1000, 0x2000, 0}
	key := append(bytes.Repeat([]byte("a"), 256), 0)
	value := append(bytes.Repeat([]byte("B"), 256), 0)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x1000, UserLen: uint32(len(key)), CopiedLen: uint32(len(key)), ProbeRet: 0, Data: key},
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 3, UserPtr: 0x2000, UserLen: uint32(len(value)), CopiedLen: uint32(len(value)), ProbeRet: 0, Data: value},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[2] != `"`+string(bytes.Repeat([]byte("a"), 256))+`"...` ||
		got.ArgParts[3] != `"`+string(bytes.Repeat([]byte("B"), 256))+`"...` {
		t.Fatalf("fsconfig limited string args = %#v", got.ArgParts)
	}
}

func TestFsconfigBinaryUsesPayloadBytesSection(t *testing.T) {
	ctx := newFsconfigBinaryContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("blob\x00")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 3, UserPtr: 0x2000, ProbeRet: 0, Data: []byte{1, 2, 3}},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[2] != `"blob"` || got.ArgParts[3] == "0x2000" {
		t.Fatalf("fsconfig binary args = %#v", got.ArgParts)
	}
}

func TestFsconfigBinaryZeroLengthFormatsEmptyBuffer(t *testing.T) {
	ctx := newFsconfigBinaryContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.Args = [6]uint64{3, 2, 0x1000, 0x2000, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("blob\x00")},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[3] != `""` {
		t.Fatalf("fsconfig zero binary value = %#v, want empty string", got.ArgParts)
	}
}

func TestFsconfigPathInvalidDfdSuppressesValueEllipsis(t *testing.T) {
	ctx := newFsconfigBinaryContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.Args = [6]uint64{3, 3, 0x1000, 0x2000, ^uint64(0)}
	value := bytes.Repeat([]byte("0"), 4096)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("key\x00")},
		{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 3, UserPtr: 0x2000, ProbeRet: 0, Data: value},
	}

	got := (&FsHandler{}).Handle(ctx)
	if strings.HasSuffix(got.ArgParts[3], "...") {
		t.Fatalf("fsconfig invalid dfd path value = %q, want no ellipsis", got.ArgParts[3])
	}
}

func TestMountUsesPayloadStringSections(t *testing.T) {
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "mount",
		Meta:    meta.NewCatalog("abbrev"),
		Args:    [6]uint64{0x1000, 0x2000, 0x3000, 0, 0x4000},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 0, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("/dev/sda1\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("/mnt\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("ext4\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 4, UserPtr: 0x4000, ProbeRet: 0, Data: []byte("rw\x00")},
		},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{StringLimit: 32},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[0] != `"/dev/sda1"` || got.ArgParts[1] != `"/mnt"` ||
		got.ArgParts[2] != `"ext4"` || got.ArgParts[4] != `"rw"` {
		t.Fatalf("mount args = %#v", got.ArgParts)
	}
}

func TestMountRemountFormatsNonNullTypeAsPointer(t *testing.T) {
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "mount",
		Meta:    meta.NewCatalog("abbrev"),
		Args:    [6]uint64{0x1000, 0x2000, 0x3000, 0x20, 0x4000},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 0, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("mount_source\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("mount_target\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("mount_fstype\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 4, UserPtr: 0x4000, ProbeRet: 0, Data: []byte("mount_data\x00")},
		},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{StringLimit: 32},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[2] != "0x3000" || got.ArgParts[4] != `"mount_data"` {
		t.Fatalf("mount remount args = %#v", got.ArgParts)
	}
}

func TestMountBindFormatsTypeAndDataAsPointers(t *testing.T) {
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "mount",
		Meta:    meta.NewCatalog("abbrev"),
		Args:    [6]uint64{0x1000, 0x2000, 0x3000, 0x1000, 0x4000},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 0, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("mount_source\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("mount_target\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 2, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("mount_fstype\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 4, UserPtr: 0x4000, ProbeRet: 0, Data: []byte("mount_data\x00")},
		},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{StringLimit: 32},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[2] != "0x3000" || got.ArgParts[4] != "0x4000" {
		t.Fatalf("mount bind args = %#v", got.ArgParts)
	}
}

func TestUmountUsesPayloadStringSection(t *testing.T) {
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "umount2",
		Meta:    meta.NewCatalog("abbrev"),
		Args:    [6]uint64{0x1000, 0},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 0, UserPtr: 0x1000, ProbeRet: 0, Data: []byte("/mnt\x00")},
		},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{StringLimit: 32},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[0] != `"/mnt"` {
		t.Fatalf("umount target = %#v", got.ArgParts)
	}
}

func newGetdentsContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "getdents64",
		Args:         [6]uint64{3, 0x3000, 512},
		Ret:          16,
		ProbeRetExit: -1,
		Decoder:      decoder,
		Meta:         meta.NewCatalog("abbrev"),
		ScMeta: meta.Syscall{
			Args:     []string{"fd", "dirent", "count"},
			ArgTypes: []string{"unsigned int", "struct linux_dirent64 *", "unsigned int"},
		},
	}
}

func TestGetdentsDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: make([]byte, 512)}
	decoder := event.NewDecoder()
	ctx := newGetdentsContext(reader, decoder)

	got := (&FsHandler{}).Handle(ctx)
	if len(got.ArgParts) != 3 {
		t.Fatalf("ArgParts len = %d, want 3", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x3000" {
		t.Fatalf("getdents dirent = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestGetdentsDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: make([]byte, 512)}
	ctx := newGetdentsContext(reader, event.NewDecoder())
	ctx.ProbeRetExit = 0

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x3000" {
		t.Fatalf("getdents dirent = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestGetdentsUsesPayloadBytesSection(t *testing.T) {
	ctx := newGetdentsContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.Ret = int64(len(makeGetdents64Dirents(24, 32)))
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x3000, ProbeRet: 0, Data: makeGetdents64Dirents(24, 32)},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x3000 /* 2 entries */" {
		t.Fatalf("getdents dirent = %q, want formatted payload section count", got.ArgParts[1])
	}
}

func TestLegacyGetdentsUsesPayloadBytesSection(t *testing.T) {
	ctx := newGetdentsContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.SysName = "getdents"
	ctx.ScMeta = meta.SyscallTable[78]
	ctx.Ret = int64(len(makeGetdents64Dirents(24, 32)))
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x3000, ProbeRet: 0, Data: makeGetdents64Dirents(24, 32)},
	}

	got := NewRegistry().Resolve("getdents").Handle(ctx)
	if got.ArgParts[1] != "0x3000 /* 2 entries */" {
		t.Fatalf("legacy getdents dirent = %q, want formatted payload section count", got.ArgParts[1])
	}
}

func TestGetdentsVerboseUsesLayoutSpecificFields(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "getdents",
			data: makeGetdentsRecord(false, 24, 4, ".."),
			want: `[{d_ino=11, d_off=22, d_reclen=24, d_name="..", d_type=DT_DIR}]`,
		},
		{
			name: "getdents64",
			data: makeGetdentsRecord(true, 24, 8, "."),
			want: `[{d_ino=11, d_off=22, d_reclen=24, d_type=DT_REG, d_name="."}]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newGetdentsContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
			ctx.SysName = test.name
			ctx.ScMeta = meta.SyscallTable[map[string]uint32{"getdents": 78, "getdents64": 217}[test.name]]
			ctx.Ret = int64(len(test.data))
			ctx.Opts = &cli.Options{Verbose: true}
			ctx.PayloadSections = []PayloadSection{
				{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x3000, ProbeRet: 0, Data: test.data},
			}

			got := NewRegistry().Resolve(test.name).Handle(ctx)
			if got.ArgParts[1] != test.want {
				t.Fatalf("verbose dirent = %q, want %q", got.ArgParts[1], test.want)
			}
		})
	}
}

func TestGetdentsFormatsZeroEntriesWithoutPayloadSection(t *testing.T) {
	ctx := newGetdentsContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.Ret = 0

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[1] != "0x3000 /* 0 entries */" {
		t.Fatalf("getdents zero dirent = %q, want zero-entry pointer comment", got.ArgParts[1])
	}
}

func TestGetdentsFormatsCountAsUnsignedInt(t *testing.T) {
	ctx := newGetdentsContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.Ret = -1
	ctx.Args = [6]uint64{uint64(^uint32(0)), 0, 0xdefaceddeadbeef}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[1] != "NULL" || got.ArgParts[2] != "3735928559" {
		t.Fatalf("getdents args = %#v, want NULL and low 32-bit count", got.ArgParts)
	}
}

func makeGetdents64Dirents(reclens ...uint16) []byte {
	var data []byte
	for _, reclen := range reclens {
		record := make([]byte, reclen)
		binary.LittleEndian.PutUint16(record[16:18], reclen)
		data = append(data, record...)
	}
	return data
}

func makeGetdentsRecord(is64 bool, reclen uint16, dType byte, name string) []byte {
	record := make([]byte, reclen)
	binary.LittleEndian.PutUint64(record[0:8], 11)
	binary.LittleEndian.PutUint64(record[8:16], 22)
	binary.LittleEndian.PutUint16(record[16:18], reclen)
	if is64 {
		record[18] = dType
		copy(record[19:], name)
		return record
	}
	copy(record[18:], name)
	record[len(record)-1] = dType
	return record
}
