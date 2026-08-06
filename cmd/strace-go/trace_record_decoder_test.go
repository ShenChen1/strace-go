package main

import (
	"testing"

	"github.com/cilium/ebpf/ringbuf"
)

func TestTraceRingbufRecordDecoderRejectsNonTraceEventV2Sample(t *testing.T) {
	decoder := traceRingbufRecordDecoder{}

	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: []byte("not-event-v2")}); ok {
		t.Fatal("traceRingbufRecordDecoder accepted a non-event-v2 sample")
	}
}

func TestTraceRecordDecoderRejectsNilRecord(t *testing.T) {
	decoder := traceRingbufRecordDecoder{}

	if _, ok := decoder.Decode(nil); ok {
		t.Fatal("traceRecordDecoder accepted a nil ringbuf record")
	}
}
