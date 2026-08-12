package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// traceStackTraceReader is the only stack-map capability needed by text
// rendering. It intentionally hides the generic ebpf.Map key/value API.
type traceStackTraceReader interface {
	ReadStackTrace(stackID uint32, ips *[127]uint64) error
}

// traceStatsReader is the only stats-map capability needed by finalization.
type traceStatsReader interface {
	ReadStats(values *[]bpfBpfStats) error
}

type traceBPFReadPorts struct {
	StackTraces traceStackTraceReader
	Stats       traceStatsReader
}

type bpfStackTraceReader struct {
	stackTraces *ebpf.Map
}

type bpfStatsReader struct {
	statsMap *ebpf.Map
}

func newTraceBPFReadPorts(objs *bpfObjects) traceBPFReadPorts {
	if objs == nil {
		return traceBPFReadPorts{}
	}
	return traceBPFReadPorts{
		StackTraces: &bpfStackTraceReader{stackTraces: objs.StackTraces},
		Stats:       &bpfStatsReader{statsMap: objs.StatsMap},
	}
}

func (r *bpfStackTraceReader) ReadStackTrace(stackID uint32, ips *[127]uint64) error {
	if r == nil || r.stackTraces == nil {
		return fmt.Errorf("stack trace map unavailable")
	}
	if ips == nil {
		return fmt.Errorf("stack trace destination is nil")
	}
	return r.stackTraces.Lookup(stackID, ips)
}

func (r *bpfStatsReader) ReadStats(values *[]bpfBpfStats) error {
	if r == nil || r.statsMap == nil {
		return fmt.Errorf("stats map unavailable")
	}
	if values == nil {
		return fmt.Errorf("stats destination is nil")
	}
	return r.statsMap.Lookup(uint32(0), values)
}

var _ traceStackTraceReader = (*bpfStackTraceReader)(nil)
var _ traceStatsReader = (*bpfStatsReader)(nil)
