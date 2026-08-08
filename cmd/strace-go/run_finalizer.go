package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"strace-go/pkg/cli"
)

type TraceRunFinalizer struct {
	opts            *cli.Options
	targetPID       int
	out             io.Writer
	statsDiagnostic io.Writer
	exitStatus      *ExitStatusCoordinator
	summary         *SummaryStats
	bpfObjs         *bpfObjects
	outPipe         io.WriteCloser
	outCmd          *exec.Cmd
}

type TraceRunFinalizerDeps struct {
	Opts            *cli.Options
	TargetPID       int
	Out             io.Writer
	StatsDiagnostic io.Writer
	ExitStatus      *ExitStatusCoordinator
	Summary         *SummaryStats
	BPFObjects      *bpfObjects
	OutPipe         io.WriteCloser
	OutCmd          *exec.Cmd
}

func newTraceRunFinalizer(deps TraceRunFinalizerDeps) *TraceRunFinalizer {
	diagnostic := deps.StatsDiagnostic
	if diagnostic == nil {
		diagnostic = os.Stderr
	}
	return &TraceRunFinalizer{
		opts:            deps.Opts,
		targetPID:       deps.TargetPID,
		out:             deps.Out,
		statsDiagnostic: diagnostic,
		exitStatus:      deps.ExitStatus,
		summary:         deps.Summary,
		bpfObjs:         deps.BPFObjects,
		outPipe:         deps.OutPipe,
		outCmd:          deps.OutCmd,
	}
}

func (s *traceSession) traceRunFinalizer() *TraceRunFinalizer {
	if s.runFinalizerCache == nil {
		s.runFinalizerCache = newTraceRunFinalizer(TraceRunFinalizerDeps{
			Opts:            s.opts,
			TargetPID:       s.targetPid,
			Out:             s.outWriter,
			StatsDiagnostic: os.Stderr,
			ExitStatus:      s.exitStatusCoordinator(),
			Summary:         s.summaryStats(),
			BPFObjects:      s.bpfObjs,
			OutPipe:         s.outPipe,
			OutCmd:          s.outCmd,
		})
	}
	return s.runFinalizerCache
}

func (f *TraceRunFinalizer) Finish() {
	if f.exitStatus != nil {
		f.exitStatus.FlushFallback(f.targetPID)
	}
	stats := collectBPFStatsFromObjects(f.bpfObjs)
	f.writeStats(stats)
	f.printSummary()
	f.closeOutputPipe()
}

func (f *TraceRunFinalizer) writeStats(stats bpfRuntimeStats) {
	if f.opts == nil {
		return
	}
	if f.opts.EventFormat == cli.EventFormatJSON {
		f.writeJSONStats(stats)
		return
	}
	f.writeTextStatsDiagnostic(stats)
}

func (f *TraceRunFinalizer) writeJSONStats(stats bpfRuntimeStats) {
	if f.out != nil {
		_ = json.NewEncoder(f.out).Encode(newJSONStatsEvent(stats))
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
	if f.opts == nil || (!f.opts.SummaryOnly && !f.opts.SummaryAndPrint) {
		return
	}
	if f.summary != nil && f.out != nil {
		f.summary.Print(f.out)
	}
}

func (f *TraceRunFinalizer) closeOutputPipe() {
	if f.outPipe == nil {
		return
	}
	_ = f.outPipe.Close()
	if f.outCmd != nil {
		_ = f.outCmd.Wait()
	}
}

func bpfStatsDiagnosticLine(stats bpfRuntimeStats) (string, bool) {
	if !stats.Available || stats.Error != "" {
		return "", false
	}
	// 只报告真正的丢事件；payload 截断是有界快照的正常结果，不算 dropped。
	if stats.RingbufReserveFail == 0 && stats.RingbufCopyFail == 0 &&
		stats.PendingUpdateFail == 0 {
		return "", false
	}
	return fmt.Sprintf(
		"strace-go: dropped events: ringbuf_reserve_fail=%d ringbuf_copy_fail=%d pending_update_fail=%d",
		stats.RingbufReserveFail,
		stats.RingbufCopyFail,
		stats.PendingUpdateFail,
	), true
}
