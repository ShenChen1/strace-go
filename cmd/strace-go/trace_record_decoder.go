package main

import (
	"github.com/cilium/ebpf/ringbuf"

	"strace-go/pkg/handler"
)

// traceRecordDecoder returns an envelope borrowed until the next Decode call;
// the synchronous reader consumes it before the decoder reuses its scratch.
type traceRecordDecoder interface {
	Decode(rec *ringbuf.Record) (traceEventEnvelope, bool)
}

// IMPACT: traceRingbufRecordDecoder is the product ringbuf boundary and accepts event v2 samples only.
// payloadSections is borrowed by one synchronous sink call and then reused.
type traceRingbufRecordDecoder struct {
	payloadSections []handler.PayloadSection
}

func newTraceRingbufRecordDecoder() *traceRingbufRecordDecoder {
	return &traceRingbufRecordDecoder{}
}

func (s *traceSession) traceRecordDecoder() traceRecordDecoder {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.recordDecoder
}

func (d *traceRingbufRecordDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	if d == nil {
		return traceEventEnvelope{}, false
	}
	if rec == nil {
		d.payloadSections = d.payloadSections[:0]
		return traceEventEnvelope{}, false
	}
	envelope, ok := decodeTraceEventV2EnvelopeInto(rec.RawSample, &d.payloadSections)
	if !ok {
		d.payloadSections = d.payloadSections[:0]
	}
	return envelope, ok
}
