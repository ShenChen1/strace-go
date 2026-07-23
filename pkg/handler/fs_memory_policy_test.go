package handler

import (
	"bytes"
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
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x3000, ProbeRet: 0, Data: []byte("dirents")},
	}

	got := (&FsHandler{}).Handle(ctx)
	if got.ArgParts[1] != "{...}" {
		t.Fatalf("getdents dirent = %q, want formatted payload section", got.ArgParts[1])
	}
}
