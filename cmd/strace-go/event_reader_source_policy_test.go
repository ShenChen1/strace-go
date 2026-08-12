package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

func TestTraceEventReaderDoesNotConstructSystemClock(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/event_reader.go"))
	if strings.Contains(source, "systemTraceClock{}") {
		t.Fatal("event reader must not construct a fallback system clock")
	}
}

func TestTraceEventReaderWithoutClockIsInertForTimedOperations(t *testing.T) {
	ringReader := &fakeRingbufReader{readErrors: []error{nil}}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader:  ringReader,
		Decoder: &acceptingRecordDecoder{},
	})

	if reader.clock != nil {
		t.Fatal("reader unexpectedly installed a fallback clock")
	}
	if got, err := reader.Read(&ringbuf.Record{}, time.Millisecond); err != nil || got != traceReadNoEvent {
		t.Fatalf("Read without clock = %v/%v, want no event/nil", got, err)
	}
	reader.DrainAfterDone(&ringbuf.Record{}, time.Millisecond)
	if len(ringReader.deadlines) != 0 {
		t.Fatalf("timed reader operations set deadlines without a clock: %v", ringReader.deadlines)
	}
}
