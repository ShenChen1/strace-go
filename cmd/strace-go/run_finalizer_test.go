package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

type fakeRunFinalizerPipe struct {
	bytes.Buffer
	closed bool
}

func (p *fakeRunFinalizerPipe) Close() error {
	p.closed = true
	return nil
}

func TestTraceRunFinalizerWritesJSONStats(t *testing.T) {
	var out bytes.Buffer
	output, err := newTraceOutput(TraceOutputDeps{Writer: &out})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		Opts:   &cli.Options{EventFormat: cli.EventFormatJSON},
		Output: output,
	})

	finalizer.writeStats(bpfRuntimeStats{
		Available:              true,
		RingbufReserveFail:     5,
		RingbufCopyFail:        6,
		PendingUpdateFail:      7,
		OrphanExit:             8,
		PendingMismatch:        9,
		LifecycleMapUpdateFail: 10,
	})

	var ev jsonStatsEvent
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &ev); err != nil {
		t.Fatalf("decode stats JSON: %v", err)
	}
	if ev.Type != "stats" || ev.RingbufReserveFail != 5 || ev.RingbufCopyFail != 6 ||
		ev.PendingUpdateFail != 7 || ev.OrphanExit != 8 || ev.PendingMismatch != 9 ||
		ev.LifecycleMapUpdateFail != 10 || !ev.Available {
		t.Fatalf("stats JSON = %+v, want populated stats event", ev)
	}
}

func TestTraceRunFinalizerWritesTextStatsDiagnostic(t *testing.T) {
	var diagnostics bytes.Buffer
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		Opts:            &cli.Options{EventFormat: cli.EventFormatText},
		StatsDiagnostic: &diagnostics,
	})

	finalizer.writeStats(bpfRuntimeStats{
		Available:              true,
		RingbufReserveFail:     1,
		RingbufCopyFail:        2,
		PendingUpdateFail:      3,
		OrphanExit:             4,
		PendingMismatch:        5,
		LifecycleMapUpdateFail: 6,
	})

	got := diagnostics.String()
	for _, want := range []string{
		"ringbuf_reserve_fail=1",
		"ringbuf_copy_fail=2",
		"pending_update_fail=3",
		"orphan_exit=4",
		"pending_mismatch=5",
		"lifecycle_map_update_fail=6",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("diagnostic = %q, missing %q", got, want)
		}
	}
}

func TestTraceRunFinalizerPrintsSummaryAndClosesPipe(t *testing.T) {
	var out bytes.Buffer
	pipe := &fakeRunFinalizerPipe{}
	summary := newSummaryStats()
	summary.Record("getpid", 1000, 0)
	output, err := newTraceOutput(TraceOutputDeps{Writer: &out, Closer: pipe})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		Opts:    &cli.Options{EventFormat: cli.EventFormatText, SummaryOnly: true},
		Summary: summary,
		Output:  output,
	})

	finalizer.Finish()

	if !strings.Contains(out.String(), "getpid") {
		t.Fatalf("summary output = %q, want getpid entry", out.String())
	}
	if !pipe.closed {
		t.Fatal("output pipe was not closed")
	}
}

func TestTraceRunFinalizerFlushesExitFallback(t *testing.T) {
	var out bytes.Buffer
	queue := newExitStatusQueue()
	queue.MarkExitedWithFallback(101, "fallback\n")
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		TargetPID: 101,
		ExitStatus: newExitStatusCoordinator(ExitStatusCoordinatorDeps{
			Queue: queue,
			Out:   &out,
		}),
	})

	finalizer.Finish()

	if out.String() != "fallback\n" {
		t.Fatalf("fallback output = %q, want fallback line", out.String())
	}
}

func TestTraceRunFinalizerReturnsOutputCloseError(t *testing.T) {
	closeErr := errors.New("output close failed")
	events := make([]string, 0, 1)
	output, err := newTraceOutput(TraceOutputDeps{
		Writer: bytes.NewBuffer(nil),
		Closer: &fakeTraceOutputCloser{events: &events, closeErr: closeErr},
	})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{Output: output})

	if err := finalizer.Finish(); !errors.Is(err, closeErr) {
		t.Fatalf("TraceRunFinalizer.Finish() error = %v, want %v", err, closeErr)
	}
}
