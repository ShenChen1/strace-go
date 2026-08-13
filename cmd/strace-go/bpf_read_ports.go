package main

import (
	"errors"
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

// traceAttachExitReader reads exact TID exit facts written by BPF. It is
// consumed only by the existing event-loop goroutine.
type traceAttachExitReader interface {
	IsExited(pid uint32) (bool, error)
}

type traceBPFReadPorts struct {
	StackTraces traceStackTraceReader
	Stats       traceStatsReader
	AttachExits traceAttachExitReader
}

type bpfStackTraceReader struct {
	stackTraces *ebpf.Map
}

type bpfStatsReader struct {
	statsMap *ebpf.Map
}

type bpfAttachExitReader struct {
	attachExited *ebpf.Map
}

func newTraceBPFReadPorts(objs *bpfObjects) traceBPFReadPorts {
	if objs == nil {
		return traceBPFReadPorts{}
	}
	return traceBPFReadPorts{
		StackTraces: &bpfStackTraceReader{stackTraces: objs.StackTraces},
		Stats:       &bpfStatsReader{statsMap: objs.StatsMap},
		AttachExits: &bpfAttachExitReader{attachExited: objs.AttachExitedMap},
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

func (r *bpfAttachExitReader) IsExited(pid uint32) (bool, error) {
	if r == nil || r.attachExited == nil {
		return false, fmt.Errorf("attach exit map unavailable")
	}
	var value uint32
	if err := r.attachExited.Lookup(pid, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("lookup attach exit fact for pid %d: %w", pid, err)
	}
	return value != 0, nil
}

var _ traceStackTraceReader = (*bpfStackTraceReader)(nil)
var _ traceStatsReader = (*bpfStatsReader)(nil)
var _ traceAttachExitReader = (*bpfAttachExitReader)(nil)
