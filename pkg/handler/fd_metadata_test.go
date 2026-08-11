package handler

import (
	"fmt"
	"testing"

	"strace-go/pkg/cli"
)

type fakeFDMetadata struct {
	paths   map[string]string
	cwds    map[int]string
	offsets map[string]int64
	stats   map[string]PathStat
}

func (f *fakeFDMetadata) FDPath(pid int, fd int32) (string, bool) {
	path, ok := f.paths[fdMetadataKey(pid, fd)]
	return path, ok
}

func (f *fakeFDMetadata) CWDPath(pid int) (string, bool) {
	path, ok := f.cwds[pid]
	return path, ok
}

func (f *fakeFDMetadata) FDStat(pid int, fd int32) (PathStat, bool) {
	path, ok := f.FDPath(pid, fd)
	if !ok {
		return PathStat{}, false
	}
	return f.PathStat(path)
}

func (f *fakeFDMetadata) FDOffset(pid int, fd int32) (int64, bool) {
	offset, ok := f.offsets[fdMetadataKey(pid, fd)]
	return offset, ok
}

func (f *fakeFDMetadata) PathStat(path string) (PathStat, bool) {
	stat, ok := f.stats[path]
	return stat, ok
}

func (f *fakeFDMetadata) EventfdInfo(int, int32, uint64, uint64, bool) string {
	return ""
}

func fdMetadataKey(pid int, fd int32) string {
	return fmt.Sprintf("%d:%d", pid, fd)
}

func TestFormatFdWithPathUsesInjectedMetadata(t *testing.T) {
	metadata := &fakeFDMetadata{
		paths: map[string]string{fdMetadataKey(101, 4): "/injected/path"},
	}
	ctx := &Context{
		Pid:        101,
		TargetPid:  101,
		Opts:       &cli.Options{ShowPaths: true, ShowPathsMode: 1},
		FdMap:      map[string]string{},
		FDMetadata: metadata,
	}

	if got := FormatFdWithPath(ctx, 4); got != "4</injected/path>" {
		t.Fatalf("FormatFdWithPath = %q, want injected path", got)
	}
}

func TestFormatFdWithPathUsesInjectedCWD(t *testing.T) {
	metadata := &fakeFDMetadata{cwds: map[int]string{202: "/injected/cwd"}}
	ctx := &Context{
		Pid:        202,
		TargetPid:  101,
		Opts:       &cli.Options{ShowPaths: true},
		FDMetadata: metadata,
	}

	h := &DefaultHandler{}
	got := h.formatFdArg(ctx, "dfd", uint64(^uint32(99)))
	if got != "AT_FDCWD</injected/cwd>" {
		t.Fatalf("formatFdArg = %q, want injected cwd", got)
	}
}

func TestUpdateCwdUsesInjectedMetadata(t *testing.T) {
	metadata := &fakeFDMetadata{cwds: map[int]string{202: "/injected/cwd"}}
	fdMap := make(map[string]string)

	UpdateCwd(101, "child", fdMap, 202, metadata)

	if got := fdMap["101:cwd"]; got != "/injected/cwd/child" {
		t.Fatalf("updated cwd = %q, want %q", got, "/injected/cwd/child")
	}
}
