package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

func TestReadTraceEventBatchHonorsBacklogLimit(t *testing.T) {
	ringReader := &fakeRingbufReader{
		readErrors: []error{nil, nil, nil},
		remaining:  []int{512, 256, 0},
	}
	decoder := &acceptingRecordDecoder{}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader:  ringReader,
		Decoder: decoder,
		Clock:   &fakeTraceClock{now: time.Unix(100, 0)},
	})
	var record ringbuf.Record

	status, err := readTraceEventBatch(reader, &record, time.Second, 2)
	if err != nil || status != traceReadHandled {
		t.Fatalf("first batch = %v/%v, want handled/nil", status, err)
	}
	if ringReader.readCalls != 2 || decoder.calls != 2 {
		t.Fatalf("first batch read/decode calls = %d/%d, want 2/2", ringReader.readCalls, decoder.calls)
	}

	status, err = readTraceEventBatch(reader, &record, time.Second, 2)
	if err != nil || status != traceReadHandled {
		t.Fatalf("second batch = %v/%v, want handled/nil", status, err)
	}
	if ringReader.readCalls != 3 || decoder.calls != 3 {
		t.Fatalf("second batch read/decode calls = %d/%d, want 3/3", ringReader.readCalls, decoder.calls)
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

func TestTraceSessionAttachPolicySnapshotsCLIState(t *testing.T) {
	opts := &cli.Options{AttachPids: []int{101, 202}}
	session := newTestTraceSessionWithOptions(opts, traceSessionDeps{})
	opts.AttachPids[0] = 303

	attachPIDs := session.sessionAttachPIDs()
	if len(attachPIDs) != 2 || attachPIDs[0] != 101 || attachPIDs[1] != 202 {
		t.Fatalf("session attach PIDs = %v, want [101 202]", attachPIDs)
	}
	if len(session.components.exitStatus.attachPids) != 2 || session.components.exitStatus.attachPids[0] != 101 {
		t.Fatalf("exit status attach PIDs = %v, want snapshot [101 202]", session.components.exitStatus.attachPids)
	}
	attachPIDs[0] = 404
	if session.sessionAttachPIDs()[0] != 101 {
		t.Fatal("session attach policy leaked its backing slice")
	}
}

func TestTraceRunStateCollectMarksCommandExit(t *testing.T) {
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{Queue: newExitStatusQueue()})
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		TargetPID:  77,
		ExitStatus: coordinator,
	})
	state := traceRunState{
		command: fakeTraceCommandWaiter{},
		cmdDone: closedTraceCommandDone(),
		clock:   &fakeTraceClock{now: time.Unix(100, 0)},
	}

	state.collect(handler)
	if !state.commandExited || state.cmdDone != nil {
		t.Fatalf("state after collect = %+v, want command exited and cmdDone cleared", state)
	}
	if !coordinator.queue.HasExited(77) {
		t.Fatalf("tracee exit was not marked: %+v", coordinator.queue)
	}
}

func TestTraceRunStateWaitsForCommandLifecycleExit(t *testing.T) {
	lifecycle := &fakeCommandLifecycleReader{}
	state := traceRunState{
		commandExited:    true,
		attachExited:     true,
		targetPID:        101,
		commandLifecycle: lifecycle,
		clock:            &fakeTraceClock{now: time.Unix(100, 0)},
	}

	if state.done() {
		t.Fatal("run state finished before command lifecycle exit")
	}
	if err := state.collect(nil); err != nil {
		t.Fatalf("collect() error = %v", err)
	}
	if state.done() {
		t.Fatal("run state finished while lifecycle exit was absent")
	}

	lifecycle.exited = true
	if err := state.collect(nil); err != nil {
		t.Fatalf("collect() after lifecycle exit error = %v", err)
	}
	if !state.done() {
		t.Fatal("run state did not finish after command lifecycle exit")
	}
}

func TestTraceRunStatePropagatesCommandLifecycleReadFailure(t *testing.T) {
	wantErr := errors.New("command lifecycle lookup failed")
	state := traceRunState{
		commandExited:    true,
		attachExited:     true,
		targetPID:        101,
		commandLifecycle: &fakeCommandLifecycleReader{err: wantErr},
		clock:            &fakeTraceClock{now: time.Unix(100, 0)},
	}

	if err := state.collect(nil); !errors.Is(err, wantErr) {
		t.Fatalf("collect() error = %v, want %v", err, wantErr)
	}
}

func TestTraceRunStateCollectStoresCommandExitFallback(t *testing.T) {
	var output bytes.Buffer
	opts := &cli.Options{EventFormat: cli.EventFormatText}
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue: newExitStatusQueue(),
		Out:   &output,
	})
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		Policy:     newTraceOutputPolicy(opts),
		TargetPID:  77,
		ExitStatus: coordinator,
		Renderer:   newTextRenderer(TextRendererDeps{Out: &output, Policy: newTraceOutputPolicy(opts)}),
	})
	state := traceRunState{
		command: fakeTraceCommandWaiter{result: traceCommandExitResult{exited: true, exitCode: 3}},
		cmdDone: closedTraceCommandDone(),
		clock:   &fakeTraceClock{now: time.Unix(100, 0)},
	}

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
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatJSON}, traceSessionDeps{
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

func TestTraceSessionRunFinalizesAfterReaderFailure(t *testing.T) {
	readErr := errors.New("reader failed during run")
	var output bytes.Buffer
	traceOutput, err := newTraceOutput(TraceOutputDeps{Writer: &output})
	if err != nil {
		t.Fatalf("newTraceOutput() error = %v", err)
	}
	session := newTestTraceSessionWithOptions(&cli.Options{}, traceSessionDeps{
		HasCommand:    true,
		CommandWaiter: fakeTraceCommandWaiter{},
		Events:        &fakeRingbufReader{readErrors: []error{readErr}},
		OutWriter:     traceOutput,
		Output:        traceOutput,
	})

	runErr := session.run()
	if !errors.Is(runErr, readErr) {
		t.Fatalf("session.run() error = %v, want %v", runErr, readErr)
	}
	if !traceOutput.closed {
		t.Fatal("session.run() returned without finalizing output")
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
			session := newTestTraceSessionWithOptions(tt.opts, traceSessionDeps{})
			if got := session.exitDrainGrace(); got != tt.want {
				t.Fatalf("exitDrainGrace() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestTraceRunStateFinishesFromAttachLifecycleState(t *testing.T) {
	state := newTraceState()
	state.seedAttachTargets([]int{101})
	runState := newTraceRunState(traceRunStateDeps{
		attachPids:  []int{101},
		attachState: state,
		clock:       &fakeTraceClock{now: time.Unix(100, 0)},
	})

	runState.collect(nil)
	if runState.attachExited {
		t.Fatal("attach run finished before target lifecycle event")
	}

	state.handleEnvelope(lifecycleEnvelopeForTask(101, 101, lifecycleExit, 0, 0))
	runState.collect(nil)
	if !runState.attachExited {
		t.Fatal("attach run did not finish after target lifecycle event")
	}
}

func TestTraceRunStateDefersCommandExitFlushUntilFinalizer(t *testing.T) {
	var output bytes.Buffer
	clock := &fakeTraceClock{now: time.Unix(200, 0)}
	coordinator := newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue: newExitStatusQueue(),
		Out:   &output,
	})
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		Policy:     newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatText}),
		TargetPID:  77,
		ExitStatus: coordinator,
		Renderer:   newTextRenderer(TextRendererDeps{Policy: newTraceOutputPolicy(&cli.Options{})}),
	})
	state := newTraceRunState(traceRunStateDeps{
		command: fakeTraceCommandWaiter{},
		clock:   clock,
	})

	state.collect(handler)
	clock.now = clock.now.Add(time.Second)
	state.collect(handler)

	if output.Len() != 0 {
		t.Fatalf("command exit output before finalizer = %q", output.String())
	}
}

func TestTraceTargetRuntimeNormalizesAndCachesExitResult(t *testing.T) {
	command := exec.Command("sh", "-c", "exit 3")
	if err := command.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}

	runtime := newTraceTargetRuntime(command)
	result := runtime.commandWaiter().Wait()
	if !result.exited || result.exitCode != 3 {
		t.Fatalf("normalized result = %+v, want exited with code 3", result)
	}
	if cached := runtime.commandWaiter().Wait(); cached != result {
		t.Fatalf("cached result = %+v, want %+v", cached, result)
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

type fakeCommandLifecycleReader struct {
	exited bool
	err    error
}

func (r *fakeCommandLifecycleReader) TargetLifecycleExited(uint32) (bool, error) {
	if r.err != nil {
		return false, r.err
	}
	return r.exited, nil
}

func (r *fakeCommandLifecycleReader) TargetLifecycleEventObserved(uint32) bool {
	return r.exited
}

func (r *fakeCommandLifecycleReader) TargetLifecycleQuiescent(uint32) bool {
	return true
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

func closedTraceCommandDone() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
