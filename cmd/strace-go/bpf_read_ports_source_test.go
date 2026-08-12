package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
	"strace-go/pkg/stacktrace"
)

type fakeTraceStackTraceReader struct {
	stackID uint32
	ips     [127]uint64
	err     error
}

func (r *fakeTraceStackTraceReader) ReadStackTrace(stackID uint32, ips *[127]uint64) error {
	r.stackID = stackID
	if r.err != nil {
		return r.err
	}
	*ips = r.ips
	return nil
}

type fakeTraceStatsReader struct {
	values []bpfBpfStats
	err    error
}

func (r *fakeTraceStatsReader) ReadStats(values *[]bpfBpfStats) error {
	if r.err != nil {
		return r.err
	}
	*values = append([]bpfBpfStats(nil), r.values...)
	return nil
}

func TestSessionReadConsumersDoNotDependOnGeneratedBPFObjects(t *testing.T) {
	root := repoRootForTest(t)
	files := []string{
		"cmd/strace-go/session_composition.go",
		"cmd/strace-go/text_renderer.go",
		"cmd/strace-go/run_finalizer.go",
		"cmd/strace-go/bpf_stats.go",
	}
	for _, name := range files {
		source := readTextFile(t, filepath.Join(root, name))
		for _, forbidden := range []string{"*bpfObjects", "*ebpf.Map", ".StackTraces.Lookup", ".StatsMap.Lookup"} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s still exposes generated BPF read dependency %q", name, forbidden)
			}
		}
	}
}

func TestTextRendererReadsStackTraceThroughTypedPort(t *testing.T) {
	var output strings.Builder
	reader := &fakeTraceStackTraceReader{ips: [127]uint64{0x1234}}
	opts := &cli.Options{StackTrace: true}
	renderer := newTextRenderer(TextRendererDeps{
		Out:         &output,
		Policy:      newTraceOutputPolicy(opts),
		StackTraces: reader,
		Resolver:    stacktrace.NewResolver(),
	})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 0, stackID: 7},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	if reader.stackID != 7 {
		t.Fatalf("stack reader id = %d, want 7", reader.stackID)
	}
	if !strings.Contains(output.String(), " > [0x1234]\n") {
		t.Fatalf("renderer output = %q, want stack frame", output.String())
	}
}

func TestTextRendererSkipsFailedStackTraceRead(t *testing.T) {
	var output strings.Builder
	reader := &fakeTraceStackTraceReader{err: errors.New("stack lookup failed")}
	opts := &cli.Options{StackTrace: true}
	renderer := newTextRenderer(TextRendererDeps{
		Out:         &output,
		Policy:      newTraceOutputPolicy(opts),
		StackTraces: reader,
		Resolver:    stacktrace.NewResolver(),
	})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 0, stackID: 7},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	if strings.Contains(output.String(), " > ") {
		t.Fatalf("renderer output = %q, want no stack frame", output.String())
	}
}

func TestCollectBPFStatsThroughTypedPort(t *testing.T) {
	reader := &fakeTraceStatsReader{values: []bpfBpfStats{
		{RingbufReserveFail: 2, PendingMismatch: 3},
		{RingbufReserveFail: 5, PendingMismatch: 7},
	}}

	stats := collectBPFStatsFromReader(reader)
	if !stats.Available || stats.RingbufReserveFail != 7 || stats.PendingMismatch != 10 {
		t.Fatalf("stats = %+v, want available 7/10", stats)
	}
}

func TestCollectBPFStatsReportsReaderFailure(t *testing.T) {
	stats := collectBPFStatsFromReader(&fakeTraceStatsReader{err: errors.New("stats lookup failed")})
	if stats.Available || !strings.Contains(stats.Error, "stats map lookup failed") {
		t.Fatalf("stats = %+v, want unavailable lookup error", stats)
	}
}
