package handler

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestFormatFdWithKernelDeviceObservation(t *testing.T) {
	ctx := &Context{
		Pid:           101,
		TargetPid:     101,
		Opts:          &cli.Options{ShowPaths: true, ShowPathsMode: 2},
		EventFDPaths:  map[int32]string{7: "/dev/null"},
		EventFDStates: map[int32]FDStateObservation{7: {FD: 7, Mode: 0020000, Rdev: (1 << 20) | 3}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7</dev/null<char 1:3>>" {
		t.Fatalf("FormatFdWithPath() = %q, want 7</dev/null<char 1:3>>", got)
	}
}
