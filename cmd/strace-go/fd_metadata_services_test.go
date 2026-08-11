package main

import (
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type fakeFDMetadataServices struct {
	paths   map[string]string
	cwds    map[int]string
	offsets map[string]int64
}

func (f *fakeFDMetadataServices) EventfdInfo(int, int32, uint64, uint64, bool) string {
	return ""
}

func (f *fakeFDMetadataServices) FDPath(pid int, fd int32) (string, bool) {
	path, ok := f.paths[fdStateKey(pid, fd)]
	return path, ok
}

func (f *fakeFDMetadataServices) FDStat(pid int, fd int32) (handler.PathStat, bool) {
	path, ok := f.FDPath(pid, fd)
	if !ok {
		return handler.PathStat{}, false
	}
	return f.PathStat(path)
}

func (f *fakeFDMetadataServices) CWDPath(pid int) (string, bool) {
	path, ok := f.cwds[pid]
	return path, ok
}

func (f *fakeFDMetadataServices) FDOffset(pid int, fd int32) (int64, bool) {
	offset, ok := f.offsets[fdStateKey(pid, fd)]
	return offset, ok
}

func (f *fakeFDMetadataServices) PathStat(string) (handler.PathStat, bool) {
	return handler.PathStat{}, false
}

func TestInitFDTrackingUsesInjectedMetadata(t *testing.T) {
	metadata := &fakeFDMetadataServices{
		offsets: map[string]int64{"101:3": 42},
	}
	paths := map[string]string{
		"101:3":   "/tmp/file",
		"101:cwd": "/tmp",
	}

	got := initFDTracking(101, paths, metadata)

	if got["101:3"] != 42 {
		t.Fatalf("initial fd offset = %d, want 42", got["101:3"])
	}
	if _, ok := got["101:cwd"]; ok {
		t.Fatal("initial offset tracking included cwd entry")
	}
}

func TestUpdateCwdStateUsesInjectedMetadata(t *testing.T) {
	metadata := &fakeFDMetadataServices{cwds: map[int]string{202: "/injected"}}
	paths := make(map[string]string)
	store := newFDStateStoreWithServices(paths, nil, handler.NewRuntime(), metadata)

	updateFDMapFromSource(
		fdStateSource{
			view:     syscallEventView{valid: true, pid: 202, tid: 202, ret: 0},
			metadata: metadata,
		},
		meta.Syscall{Name: "chdir"},
		"child",
		101,
		store.PathMap(),
	)

	if got := paths["101:cwd"]; got != "/injected/child" {
		t.Fatalf("updated cwd = %q, want %q", got, "/injected/child")
	}
}
