package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/meta"
)

func TestSummaryRecordingUsesNarrowRecorderPort(t *testing.T) {
	root := repositoryRoot(t)
	contextSource := readSourceFile(t, filepath.Join(root, "cmd", "strace-go", "syscall_event_context.go"))
	pipelineSource := readSourceFile(t, filepath.Join(root, "cmd", "strace-go", "syscall_exit_pipeline.go"))
	source := contextSource + "\n" + pipelineSource

	if !strings.Contains(contextSource, "type traceSummaryRecorder interface") {
		t.Fatal("syscall event context must declare a narrow summary recorder port")
	}
	for _, forbidden := range []string{
		"recordSummary(stats *SummaryStats)",
		"summary *SummaryStats",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("summary boundary still depends on concrete type %q", forbidden)
		}
	}
}

type fakeSummaryRecorder struct {
	calls    int
	name     string
	duration uint64
	ret      int64
}

func (r *fakeSummaryRecorder) Record(name string, duration uint64, ret int64) {
	r.calls++
	r.name = name
	r.duration = duration
	r.ret = ret
}

func TestSyscallEventContextRecordsThroughSummaryPort(t *testing.T) {
	recorder := &fakeSummaryRecorder{}
	ev := syscallEventContext{
		meta:        meta.Syscall{Name: "getpid"},
		shouldPrint: true,
		view: syscallEventView{
			valid:    true,
			duration: 12,
			ret:      -2,
		},
	}

	ev.recordSummary(recorder)
	if recorder.calls != 1 || recorder.name != "getpid" || recorder.duration != 12 || recorder.ret != -2 {
		t.Fatalf("recorder = %+v, want one getpid record", recorder)
	}

	ev.shouldPrint = false
	ev.recordSummary(recorder)
	if recorder.calls != 1 {
		t.Fatalf("filtered event called recorder %d times, want 1", recorder.calls)
	}
}

func readSourceFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
