package main

import "github.com/cilium/ebpf/ringbuf"

// traceRingbufBoundaryDecoder validates the wire envelope without decoding
// syscall fields, so reader-only capture measures the Ringbuf boundary alone.
type traceRingbufBoundaryDecoder struct{}

func (traceRingbufBoundaryDecoder) Decode(rec *ringbuf.Record) (traceEventEnvelope, bool) {
	if rec == nil {
		return traceEventEnvelope{}, false
	}
	header, _, ok := decodeTraceEventV2Header(rec.RawSample)
	if !ok {
		return traceEventEnvelope{}, false
	}
	return traceEventEnvelope{valid: true, eventType: header.eventType, pid: header.pid, tid: header.tid, sysID: header.sysID, seq: header.seq, cpu: header.cpu,
		lossEpoch: header.lossEpoch, lossTimeNS: header.lossTimeNS, recordTime: header.tsNs,
		legacyIntegrity: header.legacy}, true
}
