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
	remaining  []int
	flushErr   error
	flushCalls int
	readCalls  int
}

func (r *fakeRingbufReader) SetDeadline(deadline time.Time) {
	r.deadlines = append(r.deadlines, deadline)
}

func (r *fakeRingbufReader) ReadInto(rec *ringbuf.Record) error {
	if r.readCalls >= len(r.readErrors) {
		return ringbuf.ErrFlushed
	}
	err := r.readErrors[r.readCalls]
	if err == nil && r.readCalls < len(r.remaining) && rec != nil {
		// The test reader models the metadata populated by cilium/ebpf.
		rec.Remaining = r.remaining[r.readCalls]
	}
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

type diagnosticTraceClock struct {
	now      time.Time
	monoNS   []uint64
	monoCall int
}

func (c *diagnosticTraceClock) Now() time.Time {
	return c.now
}

func (c *diagnosticTraceClock) NowMonoNs() uint64 {
	if c.monoCall >= len(c.monoNS) {
		return 0
	}
	value := c.monoNS[c.monoCall]
	c.monoCall++
	return value
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

type scriptedRecordDecoder struct {
	results []bool
	calls   int
}

func (d *scriptedRecordDecoder) Decode(*ringbuf.Record) (traceEventEnvelope, bool) {
	result := d.calls < len(d.results) && d.results[d.calls]
	d.calls++
	return traceEventEnvelope{valid: result}, result
}

func TestTraceEventReaderReportsConsumptionStats(t *testing.T) {
	readerPort := &fakeRingbufReader{
		readErrors: []error{nil, nil},
		remaining:  []int{4096, 128},
	}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader:  readerPort,
		Decoder: &scriptedRecordDecoder{results: []bool{true, false}},
		Sink:    &recordingEventSink{},
		Clock:   &fakeTraceClock{now: time.Unix(100, 0)},
	})

	if status, err := reader.Read(&ringbuf.Record{}, time.Second); err != nil || status != traceReadHandled {
		t.Fatalf("first Read() = %v/%v, want handled/nil", status, err)
	}
	if status, err := reader.Read(&ringbuf.Record{}, time.Second); err != nil || status != traceReadNoEvent {
		t.Fatalf("second Read() = %v/%v, want no event/nil", status, err)
	}

	stats := reader.ReaderStats()
	if stats.RecordsRead != 2 || stats.RecordsDecoded != 1 || stats.RecordsInvalid != 1 ||
		stats.RecordsRouted != 1 || stats.MaxRemainingBytes != 4096 {
		t.Fatalf("reader stats = %+v, want read=2 decoded=1 invalid=1 routed=1 max_remaining=4096", stats)
	}
}

func TestTraceEventReaderMeasuresDiagnosticServiceTime(t *testing.T) {
	ringReader := &fakeRingbufReader{
		readErrors: []error{nil},
		remaining:  []int{4096},
	}
	clock := &diagnosticTraceClock{
		now:    time.Unix(100, 0),
		monoNS: []uint64{1000, 1042},
	}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader:            ringReader,
		Decoder:           &acceptingRecordDecoder{},
		Sink:              &recordingEventSink{},
		Clock:             clock,
		MeasureService:    true,
		ServiceSampleRate: 1,
	})
	record := &ringbuf.Record{RawSample: make([]byte, 96)}

	if status, err := reader.Read(record, time.Second); err != nil || status != traceReadHandled {
		t.Fatalf("diagnostic Read() = %v/%v, want handled/nil", status, err)
	}

	stats := reader.ReaderStats()
	if !stats.ServiceEnabled || stats.ServiceSampleRate != 1 || stats.ServiceRecords != 1 || stats.ServiceTimeNS != 42 ||
		stats.MaxServiceTimeNS != 42 || stats.BytesRead != 96 || stats.MaxRecordBytes != 96 ||
		stats.MinRemainingBytes != 4096 || clock.monoCall != 2 {
		t.Fatalf("diagnostic reader stats = %+v, want one 42ns measured record", stats)
	}
}

func TestTraceEventReaderSamplesDiagnosticServiceTime(t *testing.T) {
	clock := &diagnosticTraceClock{
		now:    time.Unix(100, 0),
		monoNS: []uint64{1000, 1042, 2000, 2048},
	}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader: &fakeRingbufReader{
			readErrors: []error{nil, nil, nil},
			remaining:  []int{4096, 2048, 1024},
		},
		Decoder:           &acceptingRecordDecoder{},
		Clock:             clock,
		MeasureService:    true,
		ServiceSampleRate: 2,
	})

	for i := 0; i < 3; i++ {
		if status, err := reader.Read(&ringbuf.Record{RawSample: make([]byte, 16)}, time.Second); err != nil || status != traceReadHandled {
			t.Fatalf("sampled Read(%d) = %v/%v, want handled/nil", i, status, err)
		}
	}

	stats := reader.ReaderStats()
	if stats.ServiceSampleRate != 2 || stats.ServiceRecords != 2 || stats.ServiceTimeNS != 90 || clock.monoCall != 4 {
		t.Fatalf("sampled reader stats = %+v, clock calls=%d; want two samples totaling 90ns", stats, clock.monoCall)
	}
}

func TestTraceEventReaderSkipsServiceClockWhenDiagnosticModeIsDisabled(t *testing.T) {
	clock := &diagnosticTraceClock{now: time.Unix(100, 0), monoNS: []uint64{1000, 1042}}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader:            &fakeRingbufReader{readErrors: []error{nil}},
		Decoder:           &acceptingRecordDecoder{},
		Clock:             clock,
		ServiceSampleRate: 64,
	})

	if status, err := reader.Read(&ringbuf.Record{RawSample: make([]byte, 16)}, time.Second); err != nil || status != traceReadHandled {
		t.Fatalf("non-diagnostic Read() = %v/%v, want handled/nil", status, err)
	}

	stats := reader.ReaderStats()
	if stats.ServiceEnabled || stats.ServiceSampleRate != 0 || stats.ServiceRecords != 0 || stats.ServiceTimeNS != 0 || clock.monoCall != 0 {
		t.Fatalf("non-diagnostic reader stats = %+v, clock calls=%d; want no service timing", stats, clock.monoCall)
	}
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

func TestTraceEventReaderReusesDeadlineAcrossRecords(t *testing.T) {
	ringReader := &fakeRingbufReader{
		readErrors: []error{nil, nil, os.ErrDeadlineExceeded, nil},
	}
	clock := &stepTraceClock{now: time.Unix(100, 0), step: time.Second}
	reader := newTraceEventReader(TraceEventReaderDeps{
		Reader:  ringReader,
		Decoder: &acceptingRecordDecoder{},
		Clock:   clock,
	})

	for i := 0; i < 2; i++ {
		if got, err := reader.Read(&ringbuf.Record{}, time.Second); err != nil || got != traceReadHandled {
			t.Fatalf("Read(%d) result = %v/%v, want handled/nil", i, got, err)
		}
	}
	if got, err := reader.Read(&ringbuf.Record{}, time.Second); err != nil || got != traceReadNoEvent {
		t.Fatalf("timeout Read result = %v/%v, want no event/nil", got, err)
	}
	if got, err := reader.Read(&ringbuf.Record{}, time.Second); err != nil || got != traceReadHandled {
		t.Fatalf("next-round Read result = %v/%v, want handled/nil", got, err)
	}

	if len(ringReader.deadlines) != 2 {
		t.Fatalf("deadline calls = %d, want one per wait round", len(ringReader.deadlines))
	}
	if !ringReader.deadlines[0].Equal(time.Unix(101, 0)) ||
		!ringReader.deadlines[1].Equal(time.Unix(102, 0)) {
		t.Fatalf("deadlines = %v, want [101s, 102s]", ringReader.deadlines)
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
	if stats := reader.ReaderStats(); stats.RecordsRead != 1 || stats.RecordsDecoded != 1 || stats.RecordsRouted != 1 {
		t.Fatalf("drain reader stats = %+v, want read=1 decoded=1 routed=1", stats)
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
