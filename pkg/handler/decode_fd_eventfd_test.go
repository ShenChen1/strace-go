package handler

import (
	"testing"

	"strace-go/pkg/cli"
)

const eventFDTarget = "anon_inode:[eventfd],eventfd-count=0x5,eventfd-id=17,eventfd-semaphore=1"

func TestFormatFdWithEventFDOnlyMode(t *testing.T) {
	ctx := &Context{
		Opts: cli.ParseArgs([]string{"--decode-fds=eventfd", "/bin/true"}),
		EventFDView: testEventFDStateView{paths: map[int32]string{
			7: eventFDTarget,
			8: "/dev/null",
		}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7<{eventfd-count=0x5, eventfd-id=17, eventfd-semaphore=1}>" {
		t.Fatalf("eventfd formatting = %q", got)
	}
	if got := FormatFdWithPath(ctx, 8); got != "8" {
		t.Fatalf("ordinary fd formatting = %q, want bare fd", got)
	}
}

func TestFormatFdWithPathOnlyKeepsEventFDPath(t *testing.T) {
	ctx := &Context{
		Opts: cli.ParseArgs([]string{"--decode-fds=path", "/bin/true"}),
		EventFDView: testEventFDStateView{paths: map[int32]string{
			7: eventFDTarget,
		}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7<anon_inode:[eventfd]>" {
		t.Fatalf("eventfd path formatting = %q", got)
	}
}
