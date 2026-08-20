package main

import "github.com/cilium/ebpf/ringbuf"

// traceRingbufBoundaryDecoder validates the wire envelope without decoding
// syscall fields, so reader-only capture measures the Ringbuf boundary alone.
type traceRingbufBoundaryDecoder struct{}

func (traceRingbufBoundaryDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	if rec == nil || !isTraceEventV2Sample(rec.RawSample) {
		return traceEventEnvelope{}, false
	}
	return traceEventEnvelope{valid: true}, true
}
