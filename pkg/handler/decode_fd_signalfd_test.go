package handler

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestFormatFdWithSignalFDOnlyMode(t *testing.T) {
	ctx := &Context{
		Opts: cli.ParseArgs([]string{"--decode-fds=signalfd", "/bin/true"}),
		EventFDView: testEventFDStateView{paths: map[int32]string{
			7: "signalfd:[USR2 CHLD]",
			8: "/dev/null",
		}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7<signalfd:[USR2 CHLD]>" {
		t.Fatalf("signalfd formatting = %q", got)
	}
	if got := FormatFdWithPath(ctx, 8); got != "8" {
		t.Fatalf("ordinary fd formatting = %q, want bare fd", got)
	}
}

func TestFormatFdWithPathOnlyUsesSignalFDAnonInode(t *testing.T) {
	ctx := &Context{
		Opts: cli.ParseArgs([]string{"--decode-fds=path", "/bin/true"}),
		EventFDView: testEventFDStateView{paths: map[int32]string{
			7: "signalfd:[USR2]",
		}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7<anon_inode:[signalfd]>" {
		t.Fatalf("signalfd path formatting = %q", got)
	}
}

func TestFormatFdRejectsInvalidSignalFDTarget(t *testing.T) {
	ctx := &Context{
		Opts: cli.ParseArgs([]string{"--decode-fds=signalfd", "/bin/true"}),
		EventFDView: testEventFDStateView{paths: map[int32]string{
			7: "signalfd:[USR2]>suffix",
		}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7" {
		t.Fatalf("invalid signalfd formatting = %q, want bare fd", got)
	}
}
