package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

func unsupportedABISample() *ringbuf.Record {
	raw := make([]byte, traceEventV2HeaderLen)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderVersionOffset:], traceEventV2Version)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderEventTypeOffset:], bpfEventTypeUnsupportedABI)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderLenOffset:], traceEventV2HeaderLen)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderSizeOffset:], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderPIDOffset:], 123)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderTIDOffset:], 124)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderSysIDOffset:], 173)
	return &ringbuf.Record{RawSample: raw}
}

func TestUnsupportedABIStopsBeforeSemanticRouting(t *testing.T) {
	for name, decoder := range map[string]traceRecordDecoder{
		"normal":      newTraceRingbufRecordDecoder(),
		"reader-only": traceRingbufBoundaryDecoder{},
	} {
		t.Run(name, func(t *testing.T) {
			sink := &recordingEventSink{}
			reader := newTraceEventReader(TraceEventReaderDeps{
				Reader:  &fakeRingbufReader{readErrors: []error{nil, nil}},
				Decoder: decoder, Sink: sink, Clock: &fakeTraceClock{now: time.Unix(100, 0)},
			})
			_, err := reader.Read(unsupportedABISample(), time.Second)
			if err == nil || !strings.Contains(err.Error(), "unsupported syscall ABI") || !strings.Contains(err.Error(), "tid=124") {
				t.Fatalf("Read error = %v", err)
			}
			if sink.calls != 0 {
				t.Fatal("unsupported ABI reached semantic sink")
			}
			if err := reader.Drain(&ringbuf.Record{}); err == nil {
				t.Fatal("Drain lost terminal ABI error")
			}
		})
	}
}
