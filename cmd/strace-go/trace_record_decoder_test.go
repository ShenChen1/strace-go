package main

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

func TestTraceRingbufRecordDecoderRejectsFixedWindowSample(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:          201,
		Tid:          202,
		SysId:        39,
		EventVersion: 2,
		EventType:    bpfEventTypeExit,
	}
	minSize := int(unsafe.Offsetof(eventRaw.StrArg))
	raw := rawBPFEventForTest(eventRaw, minSize)
	decoder := traceRingbufRecordDecoder{}

	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: raw}); ok {
		t.Fatal("traceRingbufRecordDecoder accepted a fixed-window sample")
	}
}

func TestTraceRecordDecoderRejectsNilRecord(t *testing.T) {
	decoder := traceRingbufRecordDecoder{}

	if _, ok := decoder.Decode(nil); ok {
		t.Fatal("traceRecordDecoder accepted a nil ringbuf record")
	}
}

func rawBPFEventForTest(eventRaw *bpfEvent, size int) []byte {
	all := unsafe.Slice((*byte)(unsafe.Pointer(eventRaw)), int(unsafe.Sizeof(*eventRaw)))
	return append([]byte(nil), all[:size]...)
}
