package handler

import (
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestDecodeScalarFormatsMmapOffsetAsHex(t *testing.T) {
	h := &DefaultHandler{}
	ctx := &Context{
		ScMeta: meta.Syscall{Name: "mmap"},
	}

	if got := h.decodeScalar(ctx, "kernel_off_t", "off", 0xcafedeadbeef000); got != "0xcafedeadbeef000" {
		t.Fatalf("mmap offset = %q", got)
	}
	if got := h.decodeScalar(ctx, "kernel_off_t", "off", 0); got != "0" {
		t.Fatalf("zero mmap offset = %q", got)
	}
}

func TestDecodeScalarFormatsAtFdcwdFromTrackedCwd(t *testing.T) {
	h := &DefaultHandler{}
	ctx := &Context{
		Pid:       42,
		TargetPid: 42,
		ScMeta:    meta.Syscall{Name: "openat"},
		Opts:      &cli.Options{ShowPaths: true},
		FdMap: map[string]string{
			"42:cwd": "/tmp/tracee-cwd",
		},
	}

	atFdcwd := ^uint64(99)
	if got := h.decodeScalar(ctx, "int", "dfd", atFdcwd); got != "AT_FDCWD</tmp/tracee-cwd>" {
		t.Fatalf("AT_FDCWD cwd = %q", got)
	}

	ctx.FdMap["42:cwd"] = "/" + strings.Repeat("x", 4095)
	if got := h.decodeScalar(ctx, "int", "dfd", atFdcwd); got != "AT_FDCWD" {
		t.Fatalf("PATH_MAX AT_FDCWD cwd = %q", got)
	}
}
