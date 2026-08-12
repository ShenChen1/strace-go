package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type TraceRunFinalizer struct {
	formatPolicy    traceFormatPolicy
	summaryPolicy   traceSummaryPolicy
	targetPID       int
	statsDiagnostic io.Writer
	exitStatus      *ExitStatusCoordinator
	summary         *SummaryStats
	bpfObjs         *bpfObjects
	output          *TraceOutput
}

type TraceRunFinalizerDeps struct {
	FormatPolicy    traceFormatPolicy
	SummaryPolicy   traceSummaryPolicy
	TargetPID       int
	StatsDiagnostic io.Writer
	ExitStatus      *ExitStatusCoordinator
	Summary         *SummaryStats
	BPFObjects      *bpfObjects
	Output          *TraceOutput
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
		bpfObjs:         deps.BPFObjects,
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
	stats := collectBPFStatsFromObjects(f.bpfObjs)
	f.writeStats(stats)
	f.printSummary()
	return f.closeOutput()
}

func (f *TraceRunFinalizer) writeStats(stats bpfRuntimeStats) {
	if f.formatPolicy == nil {
		return
	}
	if f.formatPolicy.IsJSON() {
		f.writeJSONStats(stats)
		return
	}
	f.writeTextStatsDiagnostic(stats)
}

func (f *TraceRunFinalizer) writeJSONStats(stats bpfRuntimeStats) {
	if f.output != nil {
		_ = json.NewEncoder(f.output).Encode(newJSONStatsEvent(stats))
	}
}

func (f *TraceRunFinalizer) writeTextStatsDiagnostic(stats bpfRuntimeStats) {
	line, ok := bpfStatsDiagnosticLine(stats)
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
