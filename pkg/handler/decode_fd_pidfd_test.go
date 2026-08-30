package handler

import (
	"testing"

	"strace-go/pkg/cli"
)

const pidFDTarget = "anon_inode:[pidfd],pid=1234"

func TestFormatFdWithPIDFDOnlyMode(t *testing.T) {
	ctx := &Context{
		Opts: cli.ParseArgs([]string{"--decode-fds=pidfd", "/bin/true"}),
		EventFDView: testEventFDStateView{paths: map[int32]string{
			7: pidFDTarget,
			8: "/dev/null",
		}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7<pid:1234>" {
		t.Fatalf("pidfd formatting = %q", got)
	}
	if got := FormatFdWithPath(ctx, 8); got != "8" {
		t.Fatalf("ordinary fd formatting = %q, want bare fd", got)
	}
}

func TestFormatFdWithPathOnlyKeepsPIDFDPath(t *testing.T) {
	ctx := &Context{
		Opts: cli.ParseArgs([]string{"--decode-fds=path", "/bin/true"}),
		EventFDView: testEventFDStateView{paths: map[int32]string{
			7: pidFDTarget,
		}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7<anon_inode:[pidfd]>" {
		t.Fatalf("pidfd path formatting = %q", got)
	}
}

func TestFormatFdRejectsInvalidPIDFDTarget(t *testing.T) {
	ctx := &Context{
		Opts: cli.ParseArgs([]string{"--decode-fds=pidfd", "/bin/true"}),
		EventFDView: testEventFDStateView{paths: map[int32]string{
			7: "anon_inode:[pidfd],pid=-1",
		}},
	}

	if got := FormatFdWithPath(ctx, 7); got != "7" {
		t.Fatalf("invalid pidfd formatting = %q, want bare fd", got)
	}
}
