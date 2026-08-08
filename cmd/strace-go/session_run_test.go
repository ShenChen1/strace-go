package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"strace-go/pkg/cli"
)

func TestHandleBPFRecordUsesSessionRecordDecoder(t *testing.T) {
	decoder := &fakeRecordDecoder{}
	reader := newTraceEventReader(TraceEventReaderDeps{Decoder: decoder})

	if reader.HandleRecord(&ringbuf.Record{}) {
		t.Fatal("HandleRecord should return false when decoder rejects the record")
	}
	if decoder.calls != 1 {
		t.Fatalf("decoder calls = %d, want 1", decoder.calls)
	}
}

func TestTraceRunStateCollectMarksCommandExit(t *testing.T) {
	done := make(chan traceCommandExitResult, 1)
	done <- traceCommandExitResult{exited: true}
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{Queue: newExitStatusQueue()})
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		TargetPID:  77,
		ExitStatus: coordinator,
	})
	state := traceRunState{cmdDone: done}

	state.collect(handler)
	if !state.commandExited || state.cmdDone != nil {
		t.Fatalf("state after collect = %+v, want command exited and cmdDone cleared", state)
	}
	if !coordinator.queue.HasExited(77) {
		t.Fatalf("tracee exit was not marked: %+v", coordinator.queue)
	}
}

func TestTraceRunStateCollectStoresCommandExitFallback(t *testing.T) {
	done := make(chan traceCommandExitResult, 1)
	done <- traceCommandExitResult{exited: true, exitCode: 3}
	var output bytes.Buffer
	opts := &cli.Options{EventFormat: cli.EventFormatText}
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue: newExitStatusQueue(),
		Out:   &output,
	})
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		Opts:       opts,
		TargetPID:  77,
		ExitStatus: coordinator,
		Renderer:   newTextRenderer(TextRendererDeps{Out: &output, Opts: opts}),
	})
	state := traceRunState{cmdDone: done}

	state.collect(handler)
	if output.Len() != 0 {
		t.Fatalf("fallback printed before drain finished: %q", output.String())
	}
	handler.FlushFallback()
	if output.String() != "+++ exited with 3 +++\n" {
		t.Fatalf("fallback output = %q", output.String())
	}
}

func TestFinishRunWritesJSONStatsEvent(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{
		opts:      &cli.Options{EventFormat: cli.EventFormatJSON},
		outWriter: &output,
	}

	session.finishRun()

	var ev struct {
		Type               string `json:"type"`
		RingbufReserveFail uint64 `json:"ringbuf_reserve_fail"`
		RingbufCopyFail    uint64 `json:"ringbuf_copy_fail"`
		Available          bool   `json:"available"`
		Error              string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &ev); err != nil {
		t.Fatalf("decode stats JSON: %v", err)
	}
	if ev.Type != "stats" || ev.RingbufReserveFail != 0 || ev.RingbufCopyFail != 0 || ev.Available || ev.Error == "" {
		t.Fatalf("stats JSON event = %+v, want unavailable zero stats", ev)
	}
}

func TestExitDrainGraceOnlyAppliesToJSONOutput(t *testing.T) {
	tests := []struct {
		name string
		opts *cli.Options
		want time.Duration
	}{
		{name: "nil options", opts: nil, want: 0},
		{name: "text", opts: &cli.Options{EventFormat: cli.EventFormatText}, want: 0},
		{name: "json", opts: &cli.Options{EventFormat: cli.EventFormatJSON}, want: traceExitLifecycleDrainGrace},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &traceSession{opts: tt.opts}
			if got := session.exitDrainGrace(); got != tt.want {
				t.Fatalf("exitDrainGrace() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestAnyAttachPidAliveDetectsCurrentProcess(t *testing.T) {
	if !anyAttachPidAlive([]int{os.Getpid()}) {
		t.Fatal("current process should be treated as an alive attached pid")
	}
}

func TestTraceRunStateThrottlesAttachPolling(t *testing.T) {
	state := traceRunState{attachPids: []int{os.Getpid()}}
	state.collect(nil)
	if state.attachExited || state.nextAttachPoll.IsZero() {
		t.Fatalf("state after first attach poll = %+v, want alive pid and next poll set", state)
	}

	state.attachPids = []int{1 << 30}
	state.collect(nil)
	if state.attachExited {
		t.Fatal("attach polling should be skipped before nextAttachPoll")
	}

	state.nextAttachPoll = time.Now().Add(-time.Second)
	state.collect(nil)
	if !state.attachExited {
		t.Fatal("missing attach pid should be marked exited after the throttle expires")
	}
}

type fakeRecordDecoder struct {
	calls int
}

func (d *fakeRecordDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	d.calls++
	return traceEventEnvelope{}, false
}
