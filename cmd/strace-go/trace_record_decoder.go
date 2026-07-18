package main

import (
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

type traceRecordDecoder interface {
	Decode(rec *ringbuf.Record) (traceEventEnvelope, bool)
}

type bpfEventProjector interface {
	Project(eventRaw *bpfEvent) traceEventEnvelope
}

type fixedWindowRecordDecoder struct {
	projector bpfEventProjector
}

type traceEventProjector struct{}

func (s *traceSession) traceRecordDecoder() traceRecordDecoder {
	if s.recordDecoder == nil {
		s.recordDecoder = fixedWindowRecordDecoder{projector: traceEventProjector{}}
	}
	return s.recordDecoder
}

func (d fixedWindowRecordDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	if rec == nil {
		return traceEventEnvelope{}, false
	}
	ev, ok := decodeFixedWindowBPFEvent(rec.RawSample)
	if !ok {
		return traceEventEnvelope{}, false
	}
	return d.traceEventProjector().Project(&ev), true
}

func decodeFixedWindowTraceEventEnvelope(rawSample []byte) (traceEventEnvelope, bool) {
	ev, ok := decodeFixedWindowBPFEvent(rawSample)
	if !ok {
		return traceEventEnvelope{}, false
	}
	return traceEventProjector{}.Project(&ev), true
}

func (d fixedWindowRecordDecoder) traceEventProjector() bpfEventProjector {
	if d.projector != nil {
		return d.projector
	}
	return traceEventProjector{}
}

// IMPACT: Project is the fixed BPF carrier to traceEventEnvelope migration boundary.
func (traceEventProjector) Project(eventRaw *bpfEvent) traceEventEnvelope {
	return newTraceEventEnvelopeFromBPF(eventRaw)
}

func decodeFixedWindowBPFEvent(rawSample []byte) (bpfEvent, bool) {
	var ev bpfEvent
	minSize := int(unsafe.Offsetof(ev.StrArg))
	if len(rawSample) < minSize {
		return ev, false
	}
	eventBytes := unsafe.Slice((*byte)(unsafe.Pointer(&ev)), int(unsafe.Sizeof(ev)))
	copy(eventBytes, rawSample)
	return ev, true
}
