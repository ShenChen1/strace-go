package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestRuntimeDebugWriterReportsOnlyUnknownSyscalls(t *testing.T) {
	var output bytes.Buffer
	writer := newRuntimeDebugWriter(
		true,
		&output,
		"/test/strace",
		newSyscallMetadataTable(map[uint32]meta.Syscall{39: {Name: "getpid"}}),
	)

	writer.Observe(syscallEventView{valid: true, pid: 41, sysID: 39, eventType: bpfEventTypeEnter})
	writer.Observe(syscallEventView{valid: true, pid: 41, sysID: 500, eventType: bpfEventTypeExit})
	writer.Observe(syscallEventView{valid: true, pid: 41, sysID: 500, eventType: bpfEventTypeEnter})

	const want = "/test/strace: pid 41 invalid syscall 0x1f4\n"
	if got := output.String(); got != want {
		t.Fatalf("runtime debug output = %q, want %q", got, want)
	}
}

func TestRuntimeDebugPreservesBPFSelectorAndUnknownOutput(t *testing.T) {
	opts := cli.ParseArgs([]string{"-d", "--trace=none", "/bin/true"})
	config := newTraceBPFConfig(opts)
	if !config.syscallFilter.enabled {
		t.Fatal("runtime debug disabled the BPF syscall pre-filter")
	}
	eventPolicy := newTraceEventPolicy(opts)
	filter := eventPolicy.FilterOptions()
	if filter.IsUnfiltered() || filter.MatchSyscall("read") || !filter.MatchSyscall(unknownSyscallName(500)) {
		t.Fatal("runtime debug did not preserve the trace selector's known-syscall filter")
	}
}

func TestRuntimeDebugFormatsUnknownSyscallArguments(t *testing.T) {
	view := syscallEventView{
		valid:     true,
		sysID:     500,
		eventType: bpfEventTypeExit,
		args:      [6]uint64{1, 2, 3, 4, 5, 6},
	}
	ev := syscallEventContext{
		view:        view,
		meta:        syscallMeta(view.sysID),
		shouldPrint: true,
	}
	result, shouldOutput := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{}).Handle(ev)
	want := []string{"0x1", "0x2", "0x3", "0x4", "0x5", "0x6"}
	if !shouldOutput || len(result.ArgParts) != len(want) {
		t.Fatalf("unknown result = %+v/%v, want six arguments", result, shouldOutput)
	}
	for index := range want {
		if result.ArgParts[index] != want[index] {
			t.Fatalf("unknown argument %d = %q, want %q", index, result.ArgParts[index], want[index])
		}
	}
}

type recordingRuntimeDebugObserver struct {
	views []syscallEventView
}

func (o *recordingRuntimeDebugObserver) Observe(view syscallEventView) {
	o.views = append(o.views, view)
}

func TestTraceEventDispatcherObservesRuntimeDebugBeforeOutput(t *testing.T) {
	observer := &recordingRuntimeDebugObserver{}
	dispatcher := newTraceEventDispatcher(TraceEventDispatcherDeps{
		State:        newTraceState(),
		RuntimeDebug: observer,
	})
	view := syscallEventView{valid: true, pid: 41, sysID: 500, eventType: bpfEventTypeEnter}
	dispatcher.Dispatch(traceEventEnvelope{}, TraceStateUpdate{
		kind:        traceStateSyscallEnter,
		syscallView: view,
	})
	if len(observer.views) != 1 || observer.views[0].sysID != view.sysID {
		t.Fatalf("runtime debug observations = %+v, want syscall %d", observer.views, view.sysID)
	}
}
