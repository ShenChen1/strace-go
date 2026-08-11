package main

import (
	"errors"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

type traceRingbufReader interface {
	SetDeadline(time.Time)
	ReadInto(*ringbuf.Record) error
	Flush() error
}

type traceEventSink interface {
	Handle(traceEventEnvelope)
}

// TraceEventReader owns the synchronous ringbuf boundary. It decodes and
// routes each sample before returning control to the session loop.
type TraceEventReader struct {
	reader  traceRingbufReader
	decoder traceRecordDecoder
	sink    traceEventSink
}

type TraceEventReaderDeps struct {
	Reader  traceRingbufReader
	Decoder traceRecordDecoder
	Sink    traceEventSink
}

func newTraceEventReader(deps TraceEventReaderDeps) *TraceEventReader {
	return &TraceEventReader{
		reader:  deps.Reader,
		decoder: deps.Decoder,
		sink:    deps.Sink,
	}
}

func (s *traceSession) traceEventReader() *TraceEventReader {
	components := s.componentsOrBuild()
	if components == nil {
		return nil
	}
	return components.eventReader
}

func (r *TraceEventReader) Read(rec *ringbuf.Record, timeout time.Duration) traceReadStatus {
	if r == nil || r.reader == nil {
		return traceReadClosed
	}
	r.reader.SetDeadline(time.Now().Add(timeout))
	if err := r.reader.ReadInto(rec); err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return traceReadClosed
		}
		return traceReadNoEvent
	}
	if r.HandleRecord(rec) {
		return traceReadHandled
	}
	return traceReadNoEvent
}

func (r *TraceEventReader) Drain(rec *ringbuf.Record) {
	if r == nil || r.reader == nil {
		return
	}
	if err := r.reader.Flush(); err != nil {
		return
	}
	r.reader.SetDeadline(time.Time{})
	for {
		if err := r.reader.ReadInto(rec); err != nil {
			return
		}
		r.HandleRecord(rec)
	}
}

func (r *TraceEventReader) DrainAfterDone(rec *ringbuf.Record, grace time.Duration) {
	if grace <= 0 {
		r.Drain(rec)
		return
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if r.Read(rec, traceExitDrainPollInterval) == traceReadClosed {
			return
		}
	}
	r.Drain(rec)
}

func (r *TraceEventReader) HandleRecord(rec *ringbuf.Record) bool {
	if r == nil || r.decoder == nil {
		return false
	}
	envelope, ok := r.decoder.Decode(rec)
	if !ok {
		return false
	}
	if r.sink != nil {
		r.sink.Handle(envelope)
	}
	return true
}
