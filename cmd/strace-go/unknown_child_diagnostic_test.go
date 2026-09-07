package main

import (
	"errors"
	"strings"
	"testing"
)

func TestUnknownChildDiagnosticsRenderExactMessages(t *testing.T) {
	tests := []struct {
		name   string
		action uint32
		want   string
	}{
		{name: "detach", action: lifecycleUnknownDetach, want: "trace: Detached unknown pid 202\n"},
		{name: "exit", action: lifecycleUnknownExit, want: "trace: Exit of unknown pid 202 ignored\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output strings.Builder
			waited := 0
			diagnostics := newTraceUnknownChildDiagnostics(traceUnknownChildDiagnosticDeps{
				Output:      &output,
				ProgramName: "trace",
				Reap:        true,
				Wait: func(pid int) error {
					waited = pid
					return nil
				},
			})
			diagnostics.HandleUnknownChild(test.action, 202, false)
			if got := output.String(); got != test.want {
				t.Fatalf("diagnostic = %q, want %q", got, test.want)
			}
			if test.action == lifecycleUnknownExit && waited != 202 {
				t.Fatalf("waited pid = %d, want 202", waited)
			}
			if test.action == lifecycleUnknownDetach && waited != 0 {
				t.Fatalf("detach waited for pid %d", waited)
			}
		})
	}
}

func TestUnknownChildDiagnosticsQuietExitStillReaps(t *testing.T) {
	var output strings.Builder
	waited := 0
	diagnostics := newTraceUnknownChildDiagnostics(traceUnknownChildDiagnosticDeps{
		Output: &output,
		Reap:   true,
		Wait: func(pid int) error {
			waited = pid
			return nil
		},
	})
	diagnostics.HandleUnknownChild(lifecycleUnknownExit, 303, true)
	if waited != 303 || output.Len() != 0 {
		t.Fatalf("quiet exit waited=%d output=%q, want 303 and empty", waited, output.String())
	}
}

func TestUnknownChildDiagnosticsReportsReapFailure(t *testing.T) {
	var output strings.Builder
	diagnostics := newTraceUnknownChildDiagnostics(traceUnknownChildDiagnosticDeps{
		Output:      &output,
		ProgramName: "trace",
		Reap:        true,
		Wait: func(int) error {
			return errors.New("not a child")
		},
	})
	diagnostics.HandleUnknownChild(lifecycleUnknownExit, 404, false)
	want := "trace: Cannot reap unknown pid 404: not a child\n"
	if got := output.String(); got != want {
		t.Fatalf("reap failure = %q, want %q", got, want)
	}
}

func TestDecodeForkLifecycleMasksPackedFlags(t *testing.T) {
	packedParent := uint64(0x8000)<<32 | 101
	raw := traceEventV2LifecycleSample(t, traceEventV2SampleSpec{
		pid:    101,
		tid:    101,
		action: lifecycleFork,
		args:   [6]uint64{packedParent, 202},
	})
	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decoder rejected fork lifecycle with packed flags")
	}
	if envelope.args[0] != 101 || envelope.args[1] != 202 {
		t.Fatalf("fork args = %#v, want parent 101 child 202", envelope.args)
	}
}
