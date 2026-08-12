package main

import (
	"errors"
	"fmt"
)

// traceTargetHandoff owns bootstrap target cleanup until the session exits
// successfully. It does not expose BPF target operations to the session.
type traceTargetHandoff struct {
	targetRuntime *traceTargetRuntime
	bpfRuntime    traceBPFTargetPort
	filterPIDs    []uint32
	owned         bool
}

func newTraceTargetHandoff(
	targets traceTargetConfig,
	targetRuntime *traceTargetRuntime,
	bpfRuntime traceBPFTargetPort,
	targetPID int,
) (*traceTargetHandoff, error) {
	if bpfRuntime == nil {
		return nil, fmt.Errorf("trace target BPF port is unavailable")
	}
	return &traceTargetHandoff{
		targetRuntime: targetRuntime,
		bpfRuntime:    bpfRuntime,
		filterPIDs:    traceTargetPIDs(targets.attachPIDs, targetPID),
		owned:         true,
	}, nil
}

func (h *traceTargetHandoff) Transfer() error {
	if h == nil || h.bpfRuntime == nil {
		return fmt.Errorf("trace target handoff is unavailable")
	}
	if !h.owned {
		return fmt.Errorf("trace target ownership already transferred")
	}
	h.owned = false
	return nil
}

func (h *traceTargetHandoff) Close() error {
	if h == nil || !h.owned {
		return nil
	}
	h.owned = false
	return errors.Join(
		clearFilterPids(h.bpfRuntime, h.filterPIDs),
		terminateTraceTarget(h.targetRuntime),
	)
}
