package main

// traceEventStageStats is a sampled, single-consumer view of routed-event
// stages. The counters are samples, not totals for the complete workload.
type traceEventStageStats struct {
	Enabled           bool
	SampleRate        uint64
	StateTimeNS       uint64
	StateRecords      uint64
	MaxStateTimeNS    uint64
	DispatchTimeNS    uint64
	DispatchRecords   uint64
	MaxDispatchTimeNS uint64
}

type traceEventStageStatsReader interface {
	EventStageStats() traceEventStageStats
}

type traceEventStageSample struct {
	startNS uint64
	valid   bool
}

type traceEventStageDiagnostics struct {
	clock       traceClock
	sampleRate  uint64
	sampleIndex uint64
	stats       traceEventStageStats
}

func newTraceEventStageDiagnostics(enabled bool, clock traceClock, sampleRate uint64) *traceEventStageDiagnostics {
	if !enabled || clock == nil {
		return nil
	}
	if sampleRate == 0 {
		sampleRate = 1
	}
	return &traceEventStageDiagnostics{
		clock:      clock,
		sampleRate: sampleRate,
		stats: traceEventStageStats{
			Enabled:    true,
			SampleRate: sampleRate,
		},
	}
}

func (d *traceEventStageDiagnostics) begin() traceEventStageSample {
	if d == nil || d.clock == nil {
		return traceEventStageSample{}
	}
	index := d.sampleIndex
	d.sampleIndex++
	if index%d.sampleRate != 0 {
		return traceEventStageSample{}
	}
	return traceEventStageSample{startNS: d.clock.NowMonoNs(), valid: true}
}

func (d *traceEventStageDiagnostics) now(sample traceEventStageSample) uint64 {
	if d == nil || !sample.valid || d.clock == nil {
		return 0
	}
	return d.clock.NowMonoNs()
}

func (d *traceEventStageDiagnostics) recordState(sample traceEventStageSample, endNS uint64) {
	if d == nil || !sample.valid {
		return
	}
	d.stats.StateRecords++
	d.recordDuration(&d.stats.StateTimeNS, &d.stats.MaxStateTimeNS, sample.startNS, endNS)
}

func (d *traceEventStageDiagnostics) recordDispatch(sample traceEventStageSample, startNS, endNS uint64) {
	if d == nil || !sample.valid {
		return
	}
	d.stats.DispatchRecords++
	d.recordDuration(&d.stats.DispatchTimeNS, &d.stats.MaxDispatchTimeNS, startNS, endNS)
}

func (d *traceEventStageDiagnostics) recordDuration(total, maximum *uint64, startNS, endNS uint64) {
	if d == nil || total == nil || maximum == nil || endNS < startNS {
		return
	}
	duration := endNS - startNS
	*total += duration
	if duration > *maximum {
		*maximum = duration
	}
}

func (d *traceEventStageDiagnostics) EventStageStats() traceEventStageStats {
	if d == nil {
		return traceEventStageStats{}
	}
	return d.stats
}
