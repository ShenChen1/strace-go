package main

import (
	"testing"

	"github.com/cilium/ebpf/ringbuf"
)

func TestTraceRingbufRecordDecoderReusesPayloadScratch(t *testing.T) {
	raw := traceRecordDecoderPayloadSample(t)
	decoder := newTraceRingbufRecordDecoder()

	first, ok := decoder.Decode(&ringbuf.Record{RawSample: raw})
	if !ok || len(first.payload) != 2 {
		t.Fatalf("first decode = ok:%v payload:%d, want two sections", ok, len(first.payload))
	}
	firstHeader := &first.payload[0]
	firstCapacity := cap(decoder.payloadSections)

	second, ok := decoder.Decode(&ringbuf.Record{RawSample: raw})
	if !ok || len(second.payload) != 2 {
		t.Fatalf("second decode = ok:%v payload:%d, want two sections", ok, len(second.payload))
	}
	if &second.payload[0] != firstHeader {
		t.Fatal("decoder allocated a new payload section header backing array")
	}
	if cap(decoder.payloadSections) != firstCapacity {
		t.Fatalf("payload scratch capacity changed from %d to %d", firstCapacity, cap(decoder.payloadSections))
	}
	if string(second.payload[0].Data) != "data" || string(second.payload[1].Data) != "reply" {
		t.Fatalf("reused payload sections = %+v, want stable borrowed data", second.payload)
	}
}

func TestTraceRingbufRecordDecoderPayloadScratchHasNoSteadyStateAllocations(t *testing.T) {
	raw := traceRecordDecoderPayloadSample(t)
	decoder := newTraceRingbufRecordDecoder()
	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: raw}); !ok {
		t.Fatal("warm-up payload sample was rejected")
	}

	allocs := testing.AllocsPerRun(100, func() {
		if _, ok := decoder.Decode(&ringbuf.Record{RawSample: raw}); !ok {
			t.Fatal("steady-state payload sample was rejected")
		}
	})
	if allocs != 0 {
		t.Fatalf("steady-state decoder payload allocations = %.1f, want zero", allocs)
	}
}

func BenchmarkTraceRecordDecoderPayload(b *testing.B) {
	raw := traceRecordDecoderPayloadSample(b)
	decoder := newTraceRingbufRecordDecoder()
	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: raw}); !ok {
		b.Fatal("warm-up payload sample was rejected")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := decoder.Decode(&ringbuf.Record{RawSample: raw}); !ok {
			b.Fatal("steady-state payload sample was rejected")
		}
	}
}

func TestTraceRingbufRecordDecoderResetsPayloadScratchAfterInvalidRecord(t *testing.T) {
	sysID := syscallIDByName(t, "write")
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:   100,
		tid:   100,
		sysID: sysID,
		flags: bpfEventFlagPayloadTLV,
		payload: payloadTLVBytes(t, payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     1,
			userPtr: 0x2000,
			userLen: 4,
			data:    []byte("data"),
		}),
	})
	decoder := newTraceRingbufRecordDecoder()
	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: raw}); !ok {
		t.Fatal("valid payload sample was rejected")
	}
	if len(decoder.payloadSections) == 0 {
		t.Fatal("valid decode did not populate payload scratch")
	}

	bad := append([]byte(nil), raw[:len(raw)-1]...)
	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: bad}); ok {
		t.Fatal("truncated payload sample was accepted")
	}
	if len(decoder.payloadSections) != 0 {
		t.Fatalf("invalid decode retained %d payload sections", len(decoder.payloadSections))
	}

	invalidPayload := append(payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     1,
		userPtr: 0x2000,
		userLen: 4,
		data:    []byte("data"),
	}), 0xff)
	malformed := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     100,
		tid:     100,
		sysID:   sysID,
		flags:   bpfEventFlagPayloadTLV,
		payload: invalidPayload,
	})
	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: malformed}); !ok {
		t.Fatal("malformed TLV envelope was rejected; payload fallback should remain empty")
	}
	if len(decoder.payloadSections) != 0 {
		t.Fatalf("malformed TLV retained %d partial payload sections", len(decoder.payloadSections))
	}
}

func traceRecordDecoderPayloadSample(t testing.TB) []byte {
	t.Helper()
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     1,
		userPtr: 0x2000,
		userLen: 4,
		data:    []byte("data"),
	})
	payload = append(payload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     2,
		userPtr: 0x3000,
		userLen: 5,
		data:    []byte("reply"),
	})...)
	return traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     100,
		tid:     100,
		sysID:   syscallIDByName(t, "write"),
		flags:   bpfEventFlagPayloadTLV,
		payload: payload,
	})
}

func TestTraceRingbufRecordDecoderRejectsNonTraceEventV2Sample(t *testing.T) {
	decoder := newTraceRingbufRecordDecoder()

	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: []byte("not-event-v2")}); ok {
		t.Fatal("traceRingbufRecordDecoder accepted a non-event-v2 sample")
	}
}

func TestTraceRecordDecoderRejectsNilRecord(t *testing.T) {
	decoder := newTraceRingbufRecordDecoder()
	if _, ok := decoder.Decode(&ringbuf.Record{RawSample: traceRecordDecoderPayloadSample(t)}); !ok {
		t.Fatal("valid payload sample was rejected")
	}

	if _, ok := decoder.Decode(nil); ok {
		t.Fatal("traceRecordDecoder accepted a nil ringbuf record")
	}
	if len(decoder.payloadSections) != 0 {
		t.Fatalf("nil record retained %d payload sections", len(decoder.payloadSections))
	}
}
