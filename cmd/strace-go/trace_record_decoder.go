package main

import (
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

type traceRecordDecoder interface {
	Decode(rec *ringbuf.Record) (traceEventEnvelope, bool)
}

// IMPACT: traceRingbufRecordDecoder is the product ringbuf boundary and accepts event v2 samples only.
type traceRingbufRecordDecoder struct{}

func (s *traceSession) traceRecordDecoder() traceRecordDecoder {
	if s.recordDecoder == nil {
		s.recordDecoder = traceRingbufRecordDecoder{}
	}
	return s.recordDecoder
}

func (d traceRingbufRecordDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	if rec == nil {
		return traceEventEnvelope{}, false
	}
	return decodeTraceEventV2Envelope(rec.RawSample)
}

func decodeFixedWindowTraceEventEnvelope(rawSample []byte) (traceEventEnvelope, bool) {
	ev, ok := decodeFixedWindowBPFEvent(rawSample)
	if !ok {
		return traceEventEnvelope{}, false
	}
	return newTraceEventEnvelopeFromBPF(&ev), true
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
