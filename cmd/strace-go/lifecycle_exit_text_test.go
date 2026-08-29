package main

import (
	"bytes"
	"testing"
)

func TestTraceLifecycleExitTextWriterWritesExitLine(t *testing.T) {
	var output bytes.Buffer
	renderer := &fakeExitStatusLinePort{}
	writer := newTraceLifecycleExitTextWriter(traceLifecycleExitTextWriterDeps{
		Policy:    fakeTraceExitPolicy{},
		TargetPID: 101,
		Out:       &output,
		Renderer:  renderer,
	})

	writer.WriteExitText(202, 7)

	if output.String() != "fallback\n" {
		t.Fatalf("exit text = %q, want fallback line", output.String())
	}
	if renderer.tid != 202 || renderer.status != 7 {
		t.Fatalf("renderer args = %d/%d, want 202/7", renderer.tid, renderer.status)
	}
}

func TestTraceLifecycleExitTextWriterSuppressesConfiguredLines(t *testing.T) {
	tests := []struct {
		name       string
		policy     fakeTraceExitPolicy
		hasCommand bool
		tid        int
		targetPID  int
	}{
		{name: "quiet", policy: fakeTraceExitPolicy{quiet: true}, tid: 202, targetPID: 101},
		{name: "summary", policy: fakeTraceExitPolicy{only: true}, tid: 202, targetPID: 101},
		{name: "json", policy: fakeTraceExitPolicy{json: true}, tid: 202, targetPID: 101},
		{name: "command target", hasCommand: true, tid: 101, targetPID: 101},
		{name: "separate attach target", policy: fakeTraceExitPolicy{separate: true, attachPID: 202}, tid: 202, targetPID: 101},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			writer := newTraceLifecycleExitTextWriter(traceLifecycleExitTextWriterDeps{
				Policy:     tt.policy,
				HasCommand: tt.hasCommand,
				TargetPID:  tt.targetPID,
				Out:        &output,
				Renderer:   &fakeExitStatusLinePort{},
			})

			writer.WriteExitText(tt.tid, 7)

			if output.Len() != 0 {
				t.Fatalf("suppressed exit text = %q, want empty", output.String())
			}
		})
	}
}
