package main

import (
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

type traceRecordDecoder interface {
	Decode(rec *ringbuf.Record) (traceEventEnvelope, bool)
}

type fixedWindowRecordDecoder struct{}

func (s *traceSession) traceRecordDecoder() traceRecordDecoder {
	if s.recordDecoder == nil {
		s.recordDecoder = fixedWindowRecordDecoder{}
	}
	return s.recordDecoder
}

func (d fixedWindowRecordDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	if rec == nil {
		return traceEventEnvelope{}, false
	}
	return decodeFixedWindowTraceEventEnvelope(rec.RawSample)
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
