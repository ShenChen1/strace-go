package main

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

type fakeRingbufReader struct {
	deadlines  []time.Time
	readErrors []error
	flushErr   error
	flushCalls int
	readCalls  int
}

func (r *fakeRingbufReader) SetDeadline(deadline time.Time) {
	r.deadlines = append(r.deadlines, deadline)
}

func (r *fakeRingbufReader) ReadInto(*ringbuf.Record) error {
	if r.readCalls >= len(r.readErrors) {
		return ringbuf.ErrFlushed
	}
	err := r.readErrors[r.readCalls]
	r.readCalls++
	return err
}

func (r *fakeRingbufReader) Flush() error {
	r.flushCalls++
	return r.flushErr
}

type acceptingRecordDecoder struct {
	calls int
}

func (d *acceptingRecordDecoder) Decode(*ringbuf.Record) (traceEventEnvelope, bool) {
	d.calls++
	return traceEventEnvelope{valid: true, pid: 101}, true
}

type recordingEventSink struct {
	calls int
}

type stepTraceClock struct {
	now   time.Time
	step  time.Duration
	calls int
}

func (c *stepTraceClock) Now() time.Time {
	current := c.now
	c.now = c.now.Add(c.step)
	c.calls++
	return current
}

func (c *stepTraceClock) NowMonoNs() uint64 {
	return uint64(c.now.UnixNano())
}

func (s *recordingEventSink) Handle(traceEventEnvelope) {
	s.calls++
}

func TestTraceEventReaderReadsAndRoutesRecord(t *testing.T) {
	ringReader := &fakeRingbufReader{readErrors: []error{nil}}
	decoder := &acceptingRecordDecoder{}
	sink := &recordingEventSink{}
	clock := &fakeTraceClock{now: time.Unix(100, 0)}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader:  ringReader,
		Decoder: decoder,
		Sink:    sink,
		Clock:   clock,
	})

	got, err := reader.Read(&ringbuf.Record{}, time.Second)
	if err != nil || got != traceReadHandled {
		t.Fatalf("Read result = %v/%v, want handled/nil", got, err)
	}
	if decoder.calls != 1 || sink.calls != 1 {
		t.Fatalf("decoder/sink calls = %d/%d, want 1/1", decoder.calls, sink.calls)
	}
	wantDeadline := clock.now.Add(time.Second)
	if len(ringReader.deadlines) != 1 || !ringReader.deadlines[0].Equal(wantDeadline) {
		t.Fatalf("deadlines = %v, want %s", ringReader.deadlines, wantDeadline)
	}
}

func TestTraceEventReaderDrainAfterDoneUsesInjectedClock(t *testing.T) {
	clock := &stepTraceClock{now: time.Unix(200, 0), step: time.Second}
	ringReader := &fakeRingbufReader{}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader: ringReader,
		Clock:  clock,
	})

	reader.DrainAfterDone(&ringbuf.Record{}, 100*time.Millisecond)

	if clock.calls < 2 {
		t.Fatalf("clock calls = %d, want deadline and loop time", clock.calls)
	}
	if len(ringReader.deadlines) != 1 || !ringReader.deadlines[0].IsZero() {
		t.Fatalf("drain deadlines = %v, want final zero deadline", ringReader.deadlines)
	}
}

func TestTraceEventReaderMapsReadFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want traceReadStatus
	}{
		{name: "deadline", err: os.ErrDeadlineExceeded, want: traceReadNoEvent},
		{name: "arbitrary", err: errors.New("reader failed"), want: traceReadNoEvent},
		{name: "closed", err: ringbuf.ErrClosed, want: traceReadClosed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newTraceEventReader(TraceEventReaderDeps{
				Reader:  &fakeRingbufReader{readErrors: []error{tt.err}},
				Decoder: &acceptingRecordDecoder{},
				Clock:   &fakeTraceClock{now: time.Unix(100, 0)},
			})
			got, err := reader.Read(&ringbuf.Record{}, time.Millisecond)
			if tt.name == "arbitrary" {
				if err == nil {
					t.Fatal("Read() returned nil error for arbitrary reader failure")
				}
			} else if err != nil || got != tt.want {
				t.Fatalf("Read result = %v/%v, want %v/nil", got, err, tt.want)
			}
		})
	}
}

func TestTraceEventReaderDrainFlushesAndRoutesPendingRecords(t *testing.T) {
	ringReader := &fakeRingbufReader{readErrors: []error{nil, ringbuf.ErrFlushed}}
	decoder := &acceptingRecordDecoder{}
	sink := &recordingEventSink{}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader:  ringReader,
		Decoder: decoder,
		Sink:    sink,
	})

	reader.Drain(&ringbuf.Record{})
	if ringReader.flushCalls != 1 || decoder.calls != 1 || sink.calls != 1 {
		t.Fatalf("flush/decoder/sink calls = %d/%d/%d, want 1/1/1", ringReader.flushCalls, decoder.calls, sink.calls)
	}
	if len(ringReader.deadlines) != 1 || !ringReader.deadlines[0].IsZero() {
		t.Fatalf("drain deadlines = %v, want one zero deadline", ringReader.deadlines)
	}
}

func TestTraceEventReaderDrainStopsWhenFlushFails(t *testing.T) {
	ringReader := &fakeRingbufReader{flushErr: errors.New("flush failed")}
	reader := newTraceEventReader(TraceEventReaderDeps{Reader: ringReader})

	if err := reader.Drain(&ringbuf.Record{}); err == nil {
		t.Fatal("Drain() returned nil error after Flush failure")
	}
	if ringReader.flushCalls != 1 || ringReader.readCalls != 0 {
		t.Fatalf("flush/read calls = %d/%d, want 1/0", ringReader.flushCalls, ringReader.readCalls)
	}
}

func TestTraceEventReaderDrainReturnsReadError(t *testing.T) {
	readErr := errors.New("drain read failed")
	ringReader := &fakeRingbufReader{readErrors: []error{readErr}}
	reader := newTraceEventReader(TraceEventReaderDeps{Reader: ringReader})

	err := reader.Drain(&ringbuf.Record{})
	if !errors.Is(err, readErr) {
		t.Fatalf("Drain() error = %v, want %v", err, readErr)
	}
}
