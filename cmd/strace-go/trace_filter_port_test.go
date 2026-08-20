package main

import (
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

type fakeTraceFilterPort struct {
	debug      bool
	syscall    bool
	fdMatch    bool
	hasFD      bool
	readFDs    map[int32]bool
	writeFDs   map[int32]bool
	pathFilter event.PathFilter
}

func (filter fakeTraceFilterPort) DebugEvents() bool {
	return filter.debug
}

func (filter fakeTraceFilterPort) IsUnfiltered() bool {
	return false
}

func (filter fakeTraceFilterPort) MatchSyscall(string) bool {
	return filter.syscall
}

func (filter fakeTraceFilterPort) MatchFDs([]int32) bool {
	return filter.fdMatch
}

func (filter fakeTraceFilterPort) HasFDFilter() bool {
	return filter.hasFD
}

func (filter fakeTraceFilterPort) TraceReadFD(fd int32) bool {
	return filter.readFDs[fd]
}

func (filter fakeTraceFilterPort) TraceWriteFD(fd int32) bool {
	return filter.writeFDs[fd]
}

func (filter fakeTraceFilterPort) PathFilter() event.PathFilter {
	return filter.pathFilter
}

var _ traceFilterOptions = fakeTraceFilterPort{}

func TestEventFilterConsumesInjectedPort(t *testing.T) {
	filter := fakeTraceFilterPort{
		syscall:    true,
		pathFilter: event.TracePathSet{"/tmp": true},
	}
	req := printFilterRequest{
		view:      viewWithArgs([6]uint64{3}),
		scMeta:    meta.Syscall{Name: "dup", Args: []string{"fd"}},
		targetPid: 101,
		filter:    filter,
		fdState:   testFDPathReader{paths: map[string]string{"101:3": "/tmp/input"}},
	}
	if !checkShouldPrintFromView(req) {
		t.Fatal("event filter rejected a matching injected path port")
	}

	filter.pathFilter = event.TracePathSet{"/other": true}
	req.filter = filter
	if checkShouldPrintFromView(req) {
		t.Fatal("event filter accepted a nonmatching injected path port")
	}
}

func TestEventFilterConsumesInjectedReadWriteFDPort(t *testing.T) {
	filter := fakeTraceFilterPort{
		syscall: true,
		hasFD:   true,
		readFDs: map[int32]bool{3: true},
	}
	req := printFilterRequest{
		view:   viewWithArgs([6]uint64{3}),
		scMeta: meta.Syscall{Name: "read", Args: []string{"fd", "buf", "count"}},
		filter: filter,
	}
	if !checkShouldPrintFromView(req) {
		t.Fatal("read FD filter did not use the injected port")
	}
}

func TestRawEnterFilterConsumesInjectedDebugPort(t *testing.T) {
	ev := syscallEventContext{
		view:   viewWithArgs([6]uint64{3}),
		meta:   meta.Syscall{Name: "dup", Args: []string{"fd"}},
		filter: fakeTraceFilterPort{debug: true},
	}
	if !ev.shouldEmitRawEnter(nil) {
		t.Fatal("raw enter filter did not use injected debug policy")
	}
}
