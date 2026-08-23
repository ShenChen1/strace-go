package main

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf/ringbuf"
)

func TestTraceRingbufBoundaryDecoderAcceptsValidEvent(t *testing.T) {
	record := ringbuf.Record{RawSample: validTraceEventV2Sample()}

	decoded, ok := (traceRingbufBoundaryDecoder{}).Decode(&record)

	if !ok || !decoded.valid {
		t.Fatalf("boundary decode = %+v/%v, want valid", decoded, ok)
	}
}

func TestTraceRingbufBoundaryDecoderRejectsInvalidEvent(t *testing.T) {
	record := ringbuf.Record{RawSample: []byte{1, 2, 3}}

	if _, ok := (traceRingbufBoundaryDecoder{}).Decode(&record); ok {
		t.Fatal("boundary decoder accepted a truncated event")
	}
}

func validTraceEventV2Sample() []byte {
	const size = traceEventV2HeaderLen + traceEventV2EnterBodyLen
	raw := make([]byte, size)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderVersionOffset:traceEventV2HeaderVersionOffset+traceEventV2U16Size], traceEventV2Version)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderEventTypeOffset:traceEventV2HeaderEventTypeOffset+traceEventV2U16Size], bpfEventTypeEnter)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderLenOffset:traceEventV2HeaderLenOffset+traceEventV2U16Size], traceEventV2HeaderLen)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderSizeOffset:traceEventV2HeaderSizeOffset+traceEventV2U32Size], size)
	return raw
}
