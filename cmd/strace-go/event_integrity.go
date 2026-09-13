package main

type traceHistoryInvalidator interface {
	TaintHistory()
}

// traceIntegritySnapshot reports an observation boundary, never a certified prefix.
type traceIntegritySnapshot struct {
	Epoch                   uint64   `json:"epoch"`
	StreamGaps              uint64   `json:"stream_gaps"`
	EstimatedLost           uint64   `json:"estimated_lost_events"`
	SequenceReorders        uint64   `json:"sequence_reorders"`
	TaintTransitions        uint64   `json:"taint_transitions"`
	RecoveredDomains        uint64   `json:"recovered_domains"`
	TaintedTasks            uint64   `json:"tainted_tasks"`
	CorrelationTaintedTasks uint64   `json:"correlation_tainted_tasks"`
	UnobservedTail          uint64   `json:"unobserved_tail_attempts"`
	TaintedProcesses        uint64   `json:"tainted_processes"`
	Domains                 []string `json:"domains,omitempty"`
	LegacyRecords           uint64   `json:"unsequenced_records"`
	PID                     uint32   `json:"detected_pid,omitempty"`
	TID                     uint32   `json:"detected_tid,omitempty"`
	TimestampNS             uint64   `json:"detected_timestamp_ns,omitempty"`
	LostCount               uint64   `json:"lost_count"`
	Tainted                 bool     `json:"tainted"`
	Scope                   string   `json:"scope"`
	Reason                  string   `json:"reason,omitempty"`
	DetectedAtRecord        uint64   `json:"detected_at_record,omitempty"`
	PreviousCPURecord       uint64   `json:"previous_cpu_record,omitempty"`
	CPU                     uint32   `json:"cpu"`
	ExpectedSequence        uint64   `json:"expected_seq,omitempty"`
	ObservedSequence        uint64   `json:"observed_seq,omitempty"`
	LossEpoch               uint64   `json:"loss_epoch"`
	FirstLossTimeNS         uint64   `json:"first_loss_time_ns,omitempty"`
	Discontinuities         uint64   `json:"discontinuities"`
}

// TraceIntegrity is owned by the synchronous reader, before scope admission.
type TraceIntegrity struct {
	tasks    map[uint32]traceTaskIntegrity
	cpus     map[uint32]traceCPUSequence
	records  uint64
	snapshot traceIntegritySnapshot
	state    traceHistoryInvalidator
	fdState  traceHistoryInvalidator
	notify   func(traceIntegritySnapshot)
}

type traceIntegrityDeps struct {
	State   traceHistoryInvalidator
	FDState traceHistoryInvalidator
	Notify  func(traceIntegritySnapshot)
}

func newTraceIntegrity(deps traceIntegrityDeps) *TraceIntegrity {
	return &TraceIntegrity{cpus: make(map[uint32]traceCPUSequence), tasks: make(map[uint32]traceTaskIntegrity), state: deps.State,
		fdState: deps.FDState, notify: deps.Notify,
		snapshot: traceIntegritySnapshot{Scope: "session"}}
}

func (i *TraceIntegrity) Observe(ev *traceEventEnvelope) {
	if i == nil || ev == nil {
		return
	}
	i.records++
	if ev.legacyIntegrity {
		i.snapshot.LegacyRecords++
		ev.recordIndex = i.records
		ev.tainted = i.snapshot.Tainted
		ev.integrityEpoch = i.snapshot.Epoch
		ev.correlationTainted = i.correlationTainted(ev.tid)
		return
	}
	i.snapshot.LostCount = 0
	sequence := i.observeSequence(ev)
	newLoss := ev.lossEpoch > i.snapshot.LossEpoch
	if newLoss {
		i.snapshot.LossEpoch = ev.lossEpoch
	}
	i.observeLossTime(ev.lossTimeNS)
	reason := ""
	if sequence.invalid {
		reason = "sequence_discontinuity"
	}
	producerLoss := newLoss || (ev.lossTimeNS != 0 && !i.snapshot.Tainted)
	if producerLoss {
		if sequence.gap != nil {
			sequence.gap.confirmed = true
		}
		reason = "producer_loss"
	}
	if reason != "" {
		i.setSequenceLocation(ev, sequence)
		i.taint(reason)
	}
	i.observeTask(ev)
	ev.tainted = i.snapshot.Tainted
	ev.recordIndex = i.records
	ev.integrityEpoch = i.snapshot.Epoch
	ev.correlationTainted = i.correlationTainted(ev.tid)
}

func (i *TraceIntegrity) InvalidRecord() {
	if i == nil {
		return
	}
	i.records++
	i.taint("invalid_record")
}

func (i *TraceIntegrity) Finalize(stats bpfRuntimeStats) {
	i.finalize(stats)
}

func (i *TraceIntegrity) FinalizeAtIntentionalStop() {
	if i == nil {
		return
	}
	i.abandonUnconfirmedSequenceGaps()
}

func (i *TraceIntegrity) finalize(stats bpfRuntimeStats) {
	if i == nil {
		return
	}
	i.observeLossTime(stats.IntegrityFirstTimeNS)
	if !stats.Available {
		i.taint("final_stats_unavailable")
		return
	}
	if !i.snapshot.Tainted && (stats.IntegrityFirstTimeNS != 0 || stats.RingbufReserveFail != 0 ||
		stats.RingbufCopyFail != 0 || stats.PendingUpdateFail != 0 || stats.PendingMismatch != 0 ||
		stats.LifecycleMapUpdateFail != 0 || stats.LifecycleForkFailed != 0) {
		i.taint("producer_loss_at_finalization")
	}
	if gap := i.firstUnresolvedSequenceGap(); gap != nil && !i.snapshot.Tainted {
		i.setSequenceGapLocation(gap)
		i.taintAt("sequence_gap_at_finalization", gap.detectedRecord)
	}
	tail := false
	for cpu, sequence := range stats.EventSequences {
		delta := sequence - i.cpus[uint32(cpu)].sequence
		if delta == 0 {
			continue
		}
		if delta < uint64(1)<<63 {
			tail = true
			i.snapshot.UnobservedTail += delta
		}
	}
	if tail {
		i.taint("sequence_tail_at_finalization")
	}
}

func (i *TraceIntegrity) observeLossTime(ns uint64) {
	if ns != 0 && (i.snapshot.FirstLossTimeNS == 0 || ns < i.snapshot.FirstLossTimeNS) {
		i.snapshot.FirstLossTimeNS = ns
	}
}

func (i *TraceIntegrity) taint(reason string) {
	i.taintAt(reason, i.records)
}

func (i *TraceIntegrity) taintAt(reason string, detectedRecord uint64) {
	first := !i.snapshot.Tainted
	i.snapshot.Epoch++
	i.snapshot.TaintTransitions++
	i.snapshot.Tainted = true
	i.snapshot.Reason = reason
	i.snapshot.DetectedAtRecord = detectedRecord
	if i.state != nil {
		i.state.TaintHistory()
	}
	if i.fdState != nil {
		i.fdState.TaintHistory()
	}
	if first && i.notify != nil {
		i.notify(i.Snapshot())
	}
}

func (i *TraceIntegrity) Snapshot() traceIntegritySnapshot {
	if i == nil {
		return traceIntegritySnapshot{}
	}
	snapshot := i.snapshot
	if snapshot.Tainted {
		snapshot.Domains = []string{"fd_state", "lifecycle", "output_state"}
		processes := make(map[uint32]struct{})
		for tid, task := range i.tasks {
			snapshot.TaintedTasks++
			if task.pid != 0 {
				processes[task.pid] = struct{}{}
			}
			if i.correlationTainted(tid) {
				snapshot.CorrelationTaintedTasks++
			}
		}
		snapshot.TaintedProcesses = uint64(len(processes))
		if snapshot.CorrelationTaintedTasks != 0 {
			snapshot.Domains = append(snapshot.Domains, "syscall_correlation")
		}
	}
	return snapshot
}
