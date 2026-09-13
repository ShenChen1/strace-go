package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

const traceDiagnosticServiceSampleRate uint64 = 64

type traceRingbufReader interface {
	SetDeadline(time.Time)
	ReadInto(*ringbuf.Record) error
	Flush() error
}

type traceEventSink interface {
	Handle(traceEventEnvelope)
}

type traceEventReaderStats struct {
	Integrity         traceIntegritySnapshot
	RecordsRead       uint64
	RecordsDecoded    uint64
	RecordsInvalid    uint64
	RecordsRouted     uint64
	ServiceEnabled    bool
	ServiceSampleRate uint64
	BytesRead         uint64
	MaxRecordBytes    uint64
	ReadTimeNS        uint64
	DecodeTimeNS      uint64
	SinkTimeNS        uint64
	MinRemainingBytes uint64
	ServiceTimeNS     uint64
	ServiceRecords    uint64
	MaxServiceTimeNS  uint64
	MaxRemainingBytes uint64
	StageEnabled      bool
	StageSampleRate   uint64
	StateTimeNS       uint64
	StateRecords      uint64
	MaxStateTimeNS    uint64
	DispatchTimeNS    uint64
	DispatchRecords   uint64
	MaxDispatchTimeNS uint64
}

type traceEventReaderStatsReader interface {
	ReaderStats() traceEventReaderStats
}

// TraceEventReader owns the synchronous ringbuf boundary. It decodes and
// routes each sample before returning control to the session loop.
type TraceEventReader struct {
	integrity      *TraceIntegrity
	reader         traceRingbufReader
	decoder        traceRecordDecoder
	sink           traceEventSink
	clock          traceClock
	stageStats     traceEventStageStatsReader
	deadlineActive bool
	stats          traceEventReaderStats
}

type TraceEventReaderDeps struct {
	Integrity         *TraceIntegrity
	Reader            traceRingbufReader
	Decoder           traceRecordDecoder
	Sink              traceEventSink
	Clock             traceClock
	MeasureService    bool
	ServiceSampleRate uint64
	StageStats        traceEventStageStatsReader
}

func newTraceEventReader(deps TraceEventReaderDeps) *TraceEventReader {
	serviceEnabled := deps.MeasureService && deps.Clock != nil
	serviceSampleRate := deps.ServiceSampleRate
	if !serviceEnabled {
		serviceSampleRate = 0
	} else if serviceSampleRate == 0 {
		serviceSampleRate = 1
	}
	return &TraceEventReader{
		integrity:  deps.Integrity,
		reader:     deps.Reader,
		decoder:    deps.Decoder,
		sink:       deps.Sink,
		clock:      deps.Clock,
		stageStats: deps.StageStats,
		stats: traceEventReaderStats{
			ServiceEnabled:    serviceEnabled,
			ServiceSampleRate: serviceSampleRate,
		},
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
	readStartNS, measureRead := r.startReadMeasurement()
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
	r.finishReadMeasurement(readStartNS, measureRead)
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
		readStartNS, measureRead := r.startReadMeasurement()
		if err := r.reader.ReadInto(rec); err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("drain ringbuf: %w", err)
		}
		r.finishReadMeasurement(readStartNS, measureRead)
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
	startNS, measureService := r.startServiceMeasurement()
	if measureService {
		r.stats.ServiceRecords++
	}
	envelope, ok := r.decoder.Decode(rec)
	decodeEndNS := r.monotonicNow(measureService)
	if measureService {
		r.recordStageDuration(&r.stats.DecodeTimeNS, startNS, decodeEndNS)
	}
	if !ok {
		r.stats.RecordsInvalid++
		r.integrity.InvalidRecord()
		r.finishServiceMeasurement(startNS, decodeEndNS, measureService)
		return false
	}
	r.stats.RecordsDecoded++
	r.integrity.Observe(&envelope)
	serviceEndNS := decodeEndNS
	if r.integrity != nil {
		serviceEndNS = r.monotonicNow(measureService)
	}
	if r.sink != nil {
		sinkStartNS := r.monotonicNow(measureService)
		r.sink.Handle(envelope)
		r.stats.RecordsRouted++
		sinkEndNS := r.monotonicNow(measureService)
		if measureService {
			r.recordStageDuration(&r.stats.SinkTimeNS, sinkStartNS, sinkEndNS)
		}
		serviceEndNS = sinkEndNS
	}
	r.finishServiceMeasurement(startNS, serviceEndNS, measureService)
	return true
}

func (r *TraceEventReader) ReaderStats() traceEventReaderStats {
	if r == nil {
		return traceEventReaderStats{}
	}
	stats := r.stats
	stats.Integrity = r.integrity.Snapshot()
	if r.stageStats != nil {
		stage := r.stageStats.EventStageStats()
		stats.StageEnabled = stage.Enabled
		stats.StageSampleRate = stage.SampleRate
		stats.StateTimeNS = stage.StateTimeNS
		stats.StateRecords = stage.StateRecords
		stats.MaxStateTimeNS = stage.MaxStateTimeNS
		stats.DispatchTimeNS = stage.DispatchTimeNS
		stats.DispatchRecords = stage.DispatchRecords
		stats.MaxDispatchTimeNS = stage.MaxDispatchTimeNS
	}
	return stats
}

func (r *TraceEventReader) recordRead(rec *ringbuf.Record) {
	if r == nil {
		return
	}
	r.stats.RecordsRead++
	if rec != nil {
		recordBytes := uint64(len(rec.RawSample))
		r.stats.BytesRead += recordBytes
		if recordBytes > r.stats.MaxRecordBytes {
			r.stats.MaxRecordBytes = recordBytes
		}
	}
	if rec != nil && rec.Remaining > 0 && uint64(rec.Remaining) > r.stats.MaxRemainingBytes {
		r.stats.MaxRemainingBytes = uint64(rec.Remaining)
	}
	if rec != nil && rec.Remaining >= 0 {
		remaining := uint64(rec.Remaining)
		if r.stats.RecordsRead == 1 || remaining < r.stats.MinRemainingBytes {
			r.stats.MinRemainingBytes = remaining
		}
	}
}

func (r *TraceEventReader) startReadMeasurement() (uint64, bool) {
	if r == nil || !r.shouldMeasureServiceSample(r.stats.RecordsRead) {
		return 0, false
	}
	return r.clock.NowMonoNs(), true
}

func (r *TraceEventReader) startServiceMeasurement() (uint64, bool) {
	if r == nil || r.stats.RecordsRead == 0 || !r.shouldMeasureServiceSample(r.stats.RecordsRead-1) {
		return 0, false
	}
	return r.clock.NowMonoNs(), true
}

func (r *TraceEventReader) finishReadMeasurement(startNS uint64, measured bool) {
	if r == nil || !measured {
		return
	}
	r.recordStageDuration(&r.stats.ReadTimeNS, startNS, r.clock.NowMonoNs())
}

func (r *TraceEventReader) finishServiceMeasurement(startNS, endNS uint64, measured bool) {
	if r == nil || !measured || endNS < startNS {
		return
	}
	duration := endNS - startNS
	r.stats.ServiceTimeNS += duration
	if duration > r.stats.MaxServiceTimeNS {
		r.stats.MaxServiceTimeNS = duration
	}
}

func (r *TraceEventReader) shouldMeasureServiceSample(recordIndex uint64) bool {
	return r != nil && r.stats.ServiceEnabled && r.clock != nil && r.stats.ServiceSampleRate > 0 &&
		recordIndex%r.stats.ServiceSampleRate == 0
}

func (r *TraceEventReader) monotonicNow(measured bool) uint64 {
	if r == nil || !measured || r.clock == nil {
		return 0
	}
	return r.clock.NowMonoNs()
}

func (r *TraceEventReader) recordStageDuration(target *uint64, startNS, endNS uint64) {
	if r == nil || target == nil || endNS < startNS {
		return
	}
	*target += endNS - startNS
}
