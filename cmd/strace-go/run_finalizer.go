package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type traceExitStatusFlushPort interface {
	FlushFallback(pid int)
}

type traceSummaryWriter interface {
	Print(io.Writer)
}

type traceFinalizerOutput interface {
	io.Writer
	io.Closer
}

type TraceRunFinalizer struct {
	formatPolicy    traceFormatPolicy
	summaryPolicy   traceSummaryPolicy
	targetPID       int
	statsDiagnostic io.Writer
	exitStatus      traceExitStatusFlushPort
	summary         traceSummaryWriter
	statsReader     traceStatsReader
	readerStats     traceEventReaderStatsReader
	pendingState    tracePendingStateReader
	debugPhases     traceDebugPhasePort
	output          traceFinalizerOutput
}

type TraceRunFinalizerDeps struct {
	FormatPolicy    traceFormatPolicy
	SummaryPolicy   traceSummaryPolicy
	TargetPID       int
	StatsDiagnostic io.Writer
	ExitStatus      traceExitStatusFlushPort
	Summary         traceSummaryWriter
	Stats           traceStatsReader
	ReaderStats     traceEventReaderStatsReader
	PendingState    tracePendingStateReader
	DebugPhases     traceDebugPhasePort
	Output          traceFinalizerOutput
}

func newTraceRunFinalizer(deps TraceRunFinalizerDeps) *TraceRunFinalizer {
	diagnostic := deps.StatsDiagnostic
	if diagnostic == nil {
		diagnostic = os.Stderr
	}
	return &TraceRunFinalizer{
		formatPolicy:    deps.FormatPolicy,
		summaryPolicy:   deps.SummaryPolicy,
		targetPID:       deps.TargetPID,
		statsDiagnostic: diagnostic,
		exitStatus:      deps.ExitStatus,
		summary:         deps.Summary,
		statsReader:     deps.Stats,
		readerStats:     deps.ReaderStats,
		pendingState:    deps.PendingState,
		debugPhases:     deps.DebugPhases,
		output:          deps.Output,
	}
}

func (s *traceSession) traceRunFinalizer() *TraceRunFinalizer {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.runFinalizer
}

func (f *TraceRunFinalizer) Finish() error {
	if f.exitStatus != nil {
		f.exitStatus.FlushFallback(f.targetPID)
	}
	stats := collectBPFStatsFromReader(f.statsReader)
	f.writeStats(stats)
	f.printSummary()
	if f.debugPhases != nil {
		f.debugPhases.EmitPhase("cleanup_start")
	}
	return f.closeOutput()
}

func (f *TraceRunFinalizer) writeStats(stats bpfRuntimeStats) {
	if f.formatPolicy == nil {
		return
	}
	pendingStale := f.pendingStaleCount()
	if f.formatPolicy.DiscardEvents() {
		f.writeJSONStatsDiagnostic(stats, pendingStale)
		return
	}
	if f.formatPolicy.IsJSON() {
		f.writeJSONStats(stats, pendingStale)
		return
	}
	f.writeTextStatsDiagnostic(stats, pendingStale)
}

func (f *TraceRunFinalizer) writeJSONStatsDiagnostic(stats bpfRuntimeStats, pendingStale uint64) {
	if f == nil || f.statsDiagnostic == nil {
		return
	}
	_ = json.NewEncoder(f.statsDiagnostic).Encode(newJSONStatsEvent(stats, pendingStale, f.readerStatsSnapshot()))
}

func (f *TraceRunFinalizer) pendingStaleCount() uint64 {
	if f == nil || f.pendingState == nil {
		return 0
	}
	count := f.pendingState.PendingStaleCount()
	if count <= 0 {
		return 0
	}
	return uint64(count)
}

func (f *TraceRunFinalizer) writeJSONStats(stats bpfRuntimeStats, pendingStale uint64) {
	if f.output != nil {
		_ = json.NewEncoder(f.output).Encode(newJSONStatsEvent(stats, pendingStale, f.readerStatsSnapshot()))
	}
}

func (f *TraceRunFinalizer) readerStatsSnapshot() traceEventReaderStats {
	if f == nil || f.readerStats == nil {
		return traceEventReaderStats{}
	}
	return f.readerStats.ReaderStats()
}

func (f *TraceRunFinalizer) writeTextStatsDiagnostic(stats bpfRuntimeStats, pendingStale uint64) {
	line, ok := bpfStatsDiagnosticLine(stats)
	if pendingStale > 0 {
		if ok {
			line = fmt.Sprintf("%s pending_stale=%d", line, pendingStale)
		} else {
			line = fmt.Sprintf("strace-go: event diagnostics: pending_stale=%d", pendingStale)
		}
		ok = true
	}
	if !ok || f.statsDiagnostic == nil {
		return
	}
	fmt.Fprintln(f.statsDiagnostic, line)
}

func (f *TraceRunFinalizer) printSummary() {
	if f.summaryPolicy == nil || (!f.summaryPolicy.SummaryOnly() && !f.summaryPolicy.SummaryAndPrint()) {
		return
	}
	if f.summary != nil && f.output != nil {
		f.summary.Print(f.output)
	}
}

func (f *TraceRunFinalizer) closeOutput() error {
	if f.output == nil {
		return nil
	}
	return f.output.Close()
}

func bpfStatsDiagnosticLine(stats bpfRuntimeStats) (string, bool) {
	if !stats.Available || stats.Error != "" {
		return "", false
	}
	// 报告事件完整性诊断；payload 截断是有界快照的正常结果，不算 dropped。
	if stats.RingbufReserveFail == 0 && stats.RingbufCopyFail == 0 &&
		stats.PendingUpdateFail == 0 && stats.OrphanExit == 0 && stats.PendingMismatch == 0 &&
		stats.LifecycleMapUpdateFail == 0 {
		return "", false
	}
	return fmt.Sprintf(
		"strace-go: event diagnostics: ringbuf_reserve_fail=%d ringbuf_copy_fail=%d pending_update_fail=%d orphan_exit=%d pending_mismatch=%d lifecycle_map_update_fail=%d",
		stats.RingbufReserveFail,
		stats.RingbufCopyFail,
		stats.PendingUpdateFail,
		stats.OrphanExit,
		stats.PendingMismatch,
		stats.LifecycleMapUpdateFail,
	), true
}
