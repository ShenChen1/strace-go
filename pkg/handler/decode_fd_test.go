package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestFormatFdWithKernelDeviceObservation(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		TargetPid: 101,
		Opts:      &cli.Options{ShowPaths: true, ShowPathsMode: 2},
		EventFDView: testEventFDStateView{
			paths:        map[int32]string{7: "/dev/null"},
			observations: map[int32]FDStateObservation{7: {FD: 7, Mode: 0020000, Rdev: (1 << 20) | 3}},
		},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7</dev/null<char 1:3>>" {
		t.Fatalf("FormatFdWithPath() = %q, want 7</dev/null<char 1:3>>", got)
	}
}

func TestFormatFdWithDeviceOnlyMode(t *testing.T) {
	ctx := &Context{
		Pid:       101,
		TargetPid: 101,
		Meta:      meta.NewCatalog("abbrev"),
		Opts:      &cli.Options{ShowPaths: true, ShowPathsMode: cli.DecodeFDModeDevice},
		EventFDView: testEventFDStateView{
			cwd:          "/tmp/work",
			paths:        map[int32]string{7: "/dev/null", 8: "socket:[42]"},
			observations: map[int32]FDStateObservation{7: {FD: 7, Mode: 0020000, Rdev: (1 << 20) | 3}},
		},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7</dev/null<char 1:3>>" {
		t.Fatalf("FormatFdWithPath() = %q, want device details", got)
	}
	if got := FormatFdWithPath(ctx, 8); got != "8" {
		t.Fatalf("non-device formatting = %q, want bare fd", got)
	}
	if got := (&DefaultHandler{}).formatFdArg(ctx, "dfd", uint64(^uint32(99))); got != "AT_FDCWD" {
		t.Fatalf("AT_FDCWD formatting = %q, want no cwd path", got)
	}
}
