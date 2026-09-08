package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
)

type fakeLifecycleExecRenderer struct {
	views []syscallEventView
}

func (r *fakeLifecycleExecRenderer) PrintExecDetachedThreadSupersededFromView(view syscallEventView) {
	r.views = append(r.views, view)
}

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

func TestTraceLifecycleExitTextWriterWritesThreadExecSuperseded(t *testing.T) {
	var output bytes.Buffer
	execRenderer := &fakeLifecycleExecRenderer{}
	writer := newTraceLifecycleExitTextWriter(traceLifecycleExitTextWriterDeps{
		Policy:       newTraceOutputPolicy(&cli.Options{FollowForks: true}),
		Out:          &output,
		ExecRenderer: execRenderer,
	})

	writer.WriteExecSuperseded(200, 201, 42)

	if len(execRenderer.views) != 1 {
		t.Fatalf("superseded views = %v, want one view", execRenderer.views)
	}
	view := execRenderer.views[0]
	if view.pid != 200 || view.tid != 201 || view.enterTime != 42 {
		t.Fatalf("superseded view = %+v, want pid/tid/time 200/201/42", view)
	}
}

func TestTraceLifecycleExitTextWriterSkipsSupersededWithoutFollowForks(t *testing.T) {
	execRenderer := &fakeLifecycleExecRenderer{}
	writer := newTraceLifecycleExitTextWriter(traceLifecycleExitTextWriterDeps{
		Policy:       newTraceOutputPolicy(&cli.Options{}),
		Out:          &bytes.Buffer{},
		ExecRenderer: execRenderer,
	})

	writer.WriteExecSuperseded(200, 201, 42)

	if len(execRenderer.views) != 0 {
		t.Fatalf("superseded views = %v, want none without -f", execRenderer.views)
	}
}
