package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestFormatFdWithPathPrefersTrackedFDMap(t *testing.T) {
	ctx := &Context{
		Pid:       202,
		TargetPid: 101,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 1,
		},
		FdMap: map[string]string{
			"101:4": "/dev/full",
		},
	}

	if got := FormatFdWithPath(ctx, 4); got != "4</dev/full>" {
		t.Fatalf("FormatFdWithPath = %q, want %q", got, "4</dev/full>")
	}
}

func TestFormatFdWithPathTreatsMissingTrackedFDAsClosed(t *testing.T) {
	ctx := &Context{
		Pid:       202,
		TargetPid: 101,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 1,
		},
		FdMap: map[string]string{},
	}

	if got := FormatFdWithPath(ctx, 4); got != "4" {
		t.Fatalf("FormatFdWithPath = %q, want %q", got, "4")
	}
}

func TestFormatFdWithPathDetailsTrackedTarget(t *testing.T) {
	ctx := &Context{
		Pid:       202,
		TargetPid: 101,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 2,
		},
		FdMap: map[string]string{
			"101:0": "/dev/null",
		},
	}

	if got := FormatFdWithPath(ctx, 0); got != "0</dev/null<char 1:3>>" {
		t.Fatalf("FormatFdWithPath = %q, want %q", got, "0</dev/null<char 1:3>>")
	}
}

func TestDefaultHandlerDecodesSyncFileRangeFlags(t *testing.T) {
	ctx := &Context{
		Args: [6]uint64{
			0xffffffffffffffff,
			0xdeadbeefbadc0ded,
			0xfacefeedcafef00d,
			0xffffffff,
		},
		ScMeta: meta.Syscall{
			Name:     "sync_file_range",
			Args:     []string{"fd", "offset", "nbytes", "flags"},
			ArgTypes: []string{"int", "loff_t", "loff_t", "unsigned int"},
		},
		Opts: &cli.Options{},
	}

	got := (&DefaultHandler{}).Handle(ctx).ArgParts
	want := "SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER|0xfffffff8"
	if got[3] != want {
		t.Fatalf("sync_file_range flags = %q, want %q", got[3], want)
	}
}
