package main

import (
	"errors"
	"fmt"
	"os"
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

type traceEventReaderStats struct {
	RecordsRead       uint64
	RecordsDecoded    uint64
	RecordsInvalid    uint64
	RecordsRouted     uint64
	MaxRemainingBytes uint64
}

type traceEventReaderStatsReader interface {
	ReaderStats() traceEventReaderStats
}

// TraceEventReader owns the synchronous ringbuf boundary. It decodes and
// routes each sample before returning control to the session loop.
type TraceEventReader struct {
	reader         traceRingbufReader
	decoder        traceRecordDecoder
	sink           traceEventSink
	clock          traceClock
	deadlineActive bool
	stats          traceEventReaderStats
}

type TraceEventReaderDeps struct {
	Reader  traceRingbufReader
	Decoder traceRecordDecoder
	Sink    traceEventSink
	Clock   traceClock
}

func newTraceEventReader(deps TraceEventReaderDeps) *TraceEventReader {
	return &TraceEventReader{
		reader:  deps.Reader,
		decoder: deps.Decoder,
		sink:    deps.Sink,
		clock:   deps.Clock,
	}
}

func (s *traceSession) traceEventReader() *TraceEventReader {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.eventReader
}

func (r *TraceEventReader) Read(rec *ringbuf.Record, timeout time.Duration) (traceReadStatus, error) {
	if r == nil || r.reader == nil || r.clock == nil {
		return traceReadNoEvent, nil
	}
	if !r.deadlineActive {
		r.reader.SetDeadline(r.clock.Now().Add(timeout))
		r.deadlineActive = true
	}
	if err := r.reader.ReadInto(rec); err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			r.deadlineActive = false
			return traceReadClosed, nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ringbuf.ErrFlushed) {
			r.deadlineActive = false
			return traceReadNoEvent, nil
		}
		r.deadlineActive = false
		return traceReadNoEvent, fmt.Errorf("read ringbuf: %w", err)
	}
	r.recordRead(rec)
	if r.HandleRecord(rec) {
		return traceReadHandled, nil
	}
	return traceReadNoEvent, nil
}

func (r *TraceEventReader) Drain(rec *ringbuf.Record) error {
	if r == nil || r.reader == nil {
		return nil
	}
	if err := r.reader.Flush(); err != nil {
		return fmt.Errorf("flush ringbuf: %w", err)
	}
	r.reader.SetDeadline(time.Time{})
	r.deadlineActive = false
	for {
		if err := r.reader.ReadInto(rec); err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("drain ringbuf: %w", err)
		}
		r.recordRead(rec)
		r.HandleRecord(rec)
	}
}

func (r *TraceEventReader) DrainAfterDone(rec *ringbuf.Record, grace time.Duration) error {
	if grace <= 0 {
		return r.Drain(rec)
	}
	if r == nil || r.clock == nil {
		return nil
	}
	deadline := r.clock.Now().Add(grace)
	for r.clock.Now().Before(deadline) {
		status, err := r.Read(rec, traceExitDrainPollInterval)
		if err != nil {
			return err
		}
		if status == traceReadClosed {
			return nil
		}
	}
	return r.Drain(rec)
}

func (r *TraceEventReader) HandleRecord(rec *ringbuf.Record) bool {
	if r == nil || r.decoder == nil {
		return false
	}
	envelope, ok := r.decoder.Decode(rec)
	if !ok {
		r.stats.RecordsInvalid++
		return false
	}
	r.stats.RecordsDecoded++
	if r.sink != nil {
		r.sink.Handle(envelope)
		r.stats.RecordsRouted++
	}
	return true
}

func (r *TraceEventReader) ReaderStats() traceEventReaderStats {
	if r == nil {
		return traceEventReaderStats{}
	}
	return r.stats
}

func (r *TraceEventReader) recordRead(rec *ringbuf.Record) {
	if r == nil {
		return
	}
	r.stats.RecordsRead++
	if rec != nil && rec.Remaining > 0 && uint64(rec.Remaining) > r.stats.MaxRemainingBytes {
		r.stats.MaxRemainingBytes = uint64(rec.Remaining)
	}
}
