package main

import "github.com/cilium/ebpf/ringbuf"

type traceRecordDecoder interface {
	Decode(rec *ringbuf.Record) (traceEventEnvelope, bool)
}

// IMPACT: traceRingbufRecordDecoder is the product ringbuf boundary and accepts event v2 samples only.
type traceRingbufRecordDecoder struct{}

func (s *traceSession) traceRecordDecoder() traceRecordDecoder {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.recordDecoder
}

func (d traceRingbufRecordDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	if rec == nil {
		return traceEventEnvelope{}, false
	}
	return decodeTraceEventV2Envelope(rec.RawSample)
}
