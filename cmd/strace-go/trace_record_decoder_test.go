package main

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

func TestDecodeFixedWindowBPFEventRejectsShortSample(t *testing.T) {
	var ev bpfEvent
	minSize := int(unsafe.Offsetof(ev.StrArg))

	_, ok := decodeFixedWindowBPFEvent(make([]byte, minSize-1))
	if ok {
		t.Fatal("decodeFixedWindowBPFEvent accepted a sample shorter than the fixed event header")
	}
}

func TestDecodeFixedWindowBPFEventAcceptsMinimumSample(t *testing.T) {
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

	got, ok := decodeFixedWindowBPFEvent(raw)
	if !ok {
		t.Fatal("decodeFixedWindowBPFEvent rejected a minimum-size fixed event")
	}
	if got.Pid != eventRaw.Pid || got.Tid != eventRaw.Tid || got.SysId != eventRaw.SysId || got.Ret != eventRaw.Ret {
		t.Fatalf("decoded event = %+v, want pid/tid/sysid/ret from source event", got)
	}
	if got.Args != eventRaw.Args {
		t.Fatalf("decoded args = %+v, want %+v", got.Args, eventRaw.Args)
	}
}

func TestDecodeFixedWindowTraceEventEnvelopeProjectsEnvelope(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:          101,
		Tid:          102,
		SysId:        39,
		EventVersion: 2,
		EventType:    bpfEventTypeExit,
		Ret:          101,
		Duration:     77,
		Args:         [6]uint64{1, 2, 3, 4, 5, 6},
	}
	minSize := int(unsafe.Offsetof(eventRaw.StrArg))
	raw := rawBPFEventForTest(eventRaw, minSize)

	envelope, ok := decodeFixedWindowTraceEventEnvelope(raw)
	if !ok {
		t.Fatal("decodeFixedWindowTraceEventEnvelope rejected a minimum-size fixed event")
	}
	if !envelope.valid || envelope.pid != eventRaw.Pid || envelope.tid != eventRaw.Tid {
		t.Fatalf("decoded envelope = %+v, want valid pid/tid from source event", envelope)
	}
	if envelope.sysID != eventRaw.SysId || envelope.ret != eventRaw.Ret || envelope.duration != eventRaw.Duration {
		t.Fatalf("decoded envelope = %+v, want syscall result fields from source event", envelope)
	}
	if envelope.args != eventRaw.Args {
		t.Fatalf("decoded envelope args = %+v, want %+v", envelope.args, eventRaw.Args)
	}
}

func TestFixedWindowRecordDecoderUsesProjector(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:          201,
		Tid:          202,
		SysId:        39,
		EventVersion: 2,
		EventType:    bpfEventTypeExit,
	}
	minSize := int(unsafe.Offsetof(eventRaw.StrArg))
	raw := rawBPFEventForTest(eventRaw, minSize)
	projector := &fakeBPFEventProjector{
		envelope: traceEventEnvelope{valid: true, pid: 999},
	}
	decoder := fixedWindowRecordDecoder{projector: projector}

	envelope, ok := decoder.Decode(&ringbuf.Record{RawSample: raw})
	if !ok {
		t.Fatal("fixedWindowRecordDecoder rejected a valid fixed-window sample")
	}
	if projector.calls != 1 {
		t.Fatalf("projector calls = %d, want 1", projector.calls)
	}
	if projector.event.SysId != eventRaw.SysId || projector.event.Pid != eventRaw.Pid {
		t.Fatalf("projected event = %+v, want source fixed-window event", projector.event)
	}
	if !envelope.valid || envelope.pid != 999 {
		t.Fatalf("envelope = %+v, want projector result", envelope)
	}
}

func TestTraceRecordDecoderRejectsNilRecord(t *testing.T) {
	decoder := fixedWindowRecordDecoder{}

	if _, ok := decoder.Decode(nil); ok {
		t.Fatal("traceRecordDecoder accepted a nil ringbuf record")
	}
}

func rawBPFEventForTest(eventRaw *bpfEvent, size int) []byte {
	all := unsafe.Slice((*byte)(unsafe.Pointer(eventRaw)), int(unsafe.Sizeof(*eventRaw)))
	return append([]byte(nil), all[:size]...)
}

type fakeBPFEventProjector struct {
	calls    int
	event    bpfEvent
	envelope traceEventEnvelope
}

func (p *fakeBPFEventProjector) Project(eventRaw *bpfEvent) traceEventEnvelope {
	p.calls++
	if eventRaw != nil {
		p.event = *eventRaw
	}
	return p.envelope
}
