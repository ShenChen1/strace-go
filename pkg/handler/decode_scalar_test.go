package handler

import (
	"testing"

	"strace-go/pkg/cli"
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
