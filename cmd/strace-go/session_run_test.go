package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
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

func TestNewTraceRunStateCopiesAttachDependencies(t *testing.T) {
	attachPids := []int{101, 202}
	state := newTraceRunState(traceRunStateDeps{attachPids: attachPids})
	attachPids[0] = 303

	if state.commandExited != true || state.attachExited {
		t.Fatalf("state = %+v, want no command and active attach set", state)
	}
	if len(state.attachPids) != 2 || state.attachPids[0] != 101 {
		t.Fatalf("attach pids = %v, want copied [101 202]", state.attachPids)
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
	traceOutput, err := newTraceOutput(TraceOutputDeps{Writer: &output})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	session := newTestTraceSession(traceSessionDeps{
		Opts:      &cli.Options{EventFormat: cli.EventFormatJSON},
		OutWriter: traceOutput,
		Output:    traceOutput,
	})

	session.finishRun()

	var ev struct {
		Type               string `json:"type"`
		RingbufReserveFail uint64 `json:"ringbuf_reserve_fail"`
		PendingMismatch    uint64 `json:"pending_mismatch"`
		RingbufCopyFail    uint64 `json:"ringbuf_copy_fail"`
		Available          bool   `json:"available"`
		Error              string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &ev); err != nil {
		t.Fatalf("decode stats JSON: %v", err)
	}
	if ev.Type != "stats" || ev.RingbufReserveFail != 0 || ev.PendingMismatch != 0 || ev.Available || ev.Error == "" {
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

func TestTraceRunStateUsesInjectedPIDProbe(t *testing.T) {
	clock := &fakeTraceClock{now: time.Unix(100, 0)}
	probe := &fakeTracePIDProbe{alive: false}
	state := newTraceRunState(traceRunStateDeps{
		attachPids: []int{101, 202},
		clock:      clock,
		pidProbe:   probe,
	})

	state.collect(nil)

	if !state.attachExited {
		t.Fatal("state should finish when injected PID probe reports no live process")
	}
	if probe.calls != 1 {
		t.Fatalf("PID probe calls = %d, want 1", probe.calls)
	}
}

func TestTraceRunStateUsesInjectedClockForFallback(t *testing.T) {
	now := time.Unix(200, 0)
	clock := &fakeTraceClock{now: now}
	done := make(chan traceCommandExitResult, 1)
	done <- traceCommandExitResult{exited: true}
	state := newTraceRunState(traceRunStateDeps{clock: clock})
	state.cmdDone = done

	state.collect(nil)

	want := now.Add(traceExitFallbackGrace)
	if !state.fallbackFlush.Equal(want) {
		t.Fatalf("fallback flush = %s, want %s", state.fallbackFlush, want)
	}
}

func TestExecTraceCommandWaiterNormalizesExitResult(t *testing.T) {
	command := exec.Command("sh", "-c", "exit 3")
	if err := command.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}

	result := newExecTraceCommandWaiter(command).Wait()
	if !result.exited || result.exitCode != 3 {
		t.Fatalf("normalized result = %+v, want exited with code 3", result)
	}
}

type fakeRecordDecoder struct {
	calls int
}

func (d *fakeRecordDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	d.calls++
	return traceEventEnvelope{}, false
}

type fakeTraceClock struct {
	now    time.Time
	monoNs uint64
}

func (c *fakeTraceClock) Now() time.Time {
	return c.now
}

func (c *fakeTraceClock) NowMonoNs() uint64 {
	if c.monoNs != 0 {
		return c.monoNs
	}
	return uint64(c.now.UnixNano())
}

type fakeTracePIDProbe struct {
	alive bool
	calls int
}

func (p *fakeTracePIDProbe) AnyAlive([]int) bool {
	p.calls++
	return p.alive
}
