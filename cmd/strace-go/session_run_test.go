package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"strace-go/pkg/cli"
)

func TestDecodeBPFEventRecordRejectsShortSample(t *testing.T) {
	var ev bpfEvent
	minSize := int(unsafe.Offsetof(ev.StrArg))

	_, ok := decodeBPFEventRecord(make([]byte, minSize-1))
	if ok {
		t.Fatal("decodeBPFEventRecord accepted a sample shorter than the fixed event header")
	}
}

func TestDecodeBPFEventRecordAcceptsMinimumSample(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:          101,
		Tid:          102,
		SysId:        39,
		EventVersion: 2,
		EventType:    bpfEventTypeExit,
		Ret:          101,
		Args:         [6]uint64{1, 2, 3, 4, 5, 6},
	}
	minSize := int(unsafe.Offsetof(eventRaw.StrArg))
	raw := rawBPFEventForTest(eventRaw, minSize)

	got, ok := decodeBPFEventRecord(raw)
	if !ok {
		t.Fatal("decodeBPFEventRecord rejected a minimum-size fixed event")
	}
	if got.Pid != eventRaw.Pid || got.Tid != eventRaw.Tid || got.SysId != eventRaw.SysId || got.Ret != eventRaw.Ret {
		t.Fatalf("decoded event = %+v, want pid/tid/sysid/ret from source event", got)
	}
	if got.Args != eventRaw.Args {
		t.Fatalf("decoded args = %+v, want %+v", got.Args, eventRaw.Args)
	}
}

func TestTraceRunStateCollectMarksCommandExit(t *testing.T) {
	done := make(chan struct{})
	close(done)
	session := &traceSession{targetPid: 77}
	state := traceRunState{cmdDone: done}

	state.collect(session)
	if !state.commandExited || state.cmdDone != nil {
		t.Fatalf("state after collect = %+v, want command exited and cmdDone cleared", state)
	}
	if !session.exitedTracees[77] {
		t.Fatalf("tracee exit was not marked: %+v", session.exitedTracees)
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

func TestAnyAttachPidAliveDetectsCurrentProcess(t *testing.T) {
	if !anyAttachPidAlive([]int{os.Getpid()}) {
		t.Fatal("current process should be treated as an alive attached pid")
	}
}

func TestTraceRunStateThrottlesAttachPolling(t *testing.T) {
	state := traceRunState{attachPids: []int{os.Getpid()}}
	state.collect(&traceSession{})
	if state.attachExited || state.nextAttachPoll.IsZero() {
		t.Fatalf("state after first attach poll = %+v, want alive pid and next poll set", state)
	}

	state.attachPids = []int{1 << 30}
	state.collect(&traceSession{})
	if state.attachExited {
		t.Fatal("attach polling should be skipped before nextAttachPoll")
	}

	state.nextAttachPoll = time.Now().Add(-time.Second)
	state.collect(&traceSession{})
	if !state.attachExited {
		t.Fatal("missing attach pid should be marked exited after the throttle expires")
	}
}

func TestTransientRingbufReadError(t *testing.T) {
	if !isTransientRingbufReadError(os.ErrDeadlineExceeded) {
		t.Fatal("deadline exceeded should be a transient ringbuf read result")
	}
	if !isTransientRingbufReadError(ringbuf.ErrFlushed) {
		t.Fatal("ringbuf flush should be a transient ringbuf read result")
	}
	if isTransientRingbufReadError(errors.New("bad sample")) {
		t.Fatal("arbitrary errors should not be treated as transient ringbuf results")
	}
}

func rawBPFEventForTest(eventRaw *bpfEvent, size int) []byte {
	all := unsafe.Slice((*byte)(unsafe.Pointer(eventRaw)), int(unsafe.Sizeof(*eventRaw)))
	return append([]byte(nil), all[:size]...)
}
