package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type jsonIntegrityEvent struct {
	Type string `json:"type"`
	traceIntegritySnapshot
}

type traceRecordIntegrity struct {
	Epoch              uint64                 `json:"integrity_epoch,omitempty"`
	CorrelationTainted bool                   `json:"correlation_tainted,omitempty"`
	Unsequenced        bool                   `json:"unsequenced,omitempty"`
	Domains            *traceIntegrityDomains `json:"tainted_domains,omitempty"`
	CPU                uint32                 `json:"cpu,omitempty"`
	Sequence           uint64                 `json:"seq,omitempty"`
	LossEpoch          uint64                 `json:"loss_epoch,omitempty"`
	Record             uint64                 `json:"record_index,omitempty"`
	Tainted            bool                   `json:"tainted,omitempty"`
}

func (ev traceEventEnvelope) recordIntegrity() traceRecordIntegrity {
	return traceRecordIntegrity{CPU: ev.cpu, Sequence: ev.seq, LossEpoch: ev.lossEpoch,
		Record: ev.recordIndex, Tainted: ev.tainted, Epoch: ev.integrityEpoch,
		CorrelationTainted: ev.correlationTainted, Unsequenced: ev.legacyIntegrity,
		Domains: integrityRecordDomains(ev.tainted, ev.correlationTainted)}
}

type traceIntegrityDomains []string

var integrityHistoryDomains = traceIntegrityDomains{"fd_state", "lifecycle", "output_state"}
var integrityAllDomains = traceIntegrityDomains{"fd_state", "lifecycle", "output_state", "syscall_correlation"}

func integrityRecordDomains(tainted, correlation bool) *traceIntegrityDomains {
	if !tainted {
		return nil
	}
	if correlation {
		return &integrityAllDomains
	}
	return &integrityHistoryDomains
}

func appendJSONRecordIntegrity(dst []byte, integrity traceRecordIntegrity) []byte {
	b := jsonLineBuilder{data: dst}
	b.uintField(`"cpu":`, uint64(integrity.CPU), true)
	b.uintField(`"seq":`, integrity.Sequence, true)
	b.uintField(`"loss_epoch":`, integrity.LossEpoch, true)
	b.uintField(`"record_index":`, integrity.Record, true)
	b.boolField(`"tainted":`, integrity.Tainted, true)
	b.uintField(`"integrity_epoch":`, integrity.Epoch, true)
	b.boolField(`"correlation_tainted":`, integrity.CorrelationTainted, true)
	b.boolField(`"unsequenced":`, integrity.Unsequenced, true)
	if integrity.Domains != nil {
		b.stringArrayField(`"tainted_domains":`, *integrity.Domains)
	}
	return b.data
}

func traceIntegrityReporter(policy traceFormatPolicy, writer *JSONEventWriter, diagnostic io.Writer) func(traceIntegritySnapshot) {
	return func(snapshot traceIntegritySnapshot) {
		event := jsonIntegrityEvent{Type: "integrity", traceIntegritySnapshot: snapshot}
		if policy != nil && policy.IsJSON() && !policy.DiscardEvents() {
			writer.encode(event)
			return
		}
		if diagnostic == nil {
			return
		}
		if policy != nil && (policy.DiscardEvents() || isTraceDebugPhasesPolicy(policy)) {
			_ = json.NewEncoder(diagnostic).Encode(event)
			return
		}
		fmt.Fprintf(diagnostic, "strace-go: WARNING: tracing integrity degraded scope=session reason=%s detected_at_record=%d cpu=%d expected_seq=%d observed_seq=%d loss_epoch=%d first_loss_time_ns=%d; historical FD/path/lifecycle state may be incomplete; correlation requires a fresh pair\n",
			snapshot.Reason, snapshot.DetectedAtRecord, snapshot.CPU, snapshot.ExpectedSequence,
			snapshot.ObservedSequence, snapshot.LossEpoch, snapshot.FirstLossTimeNS)
	}
}

func writeIntegritySummary(out io.Writer, snapshot traceIntegritySnapshot, stats bpfRuntimeStats) {
	if out == nil || (!snapshot.Tainted && snapshot.LegacyRecords == 0) {
		return
	}
	fmt.Fprintf(out, "strace-go: integrity summary: stream_gaps=%d estimated_lost_events=%d unobserved_tail_attempts=%d sequence_reorders=%d taint_transitions=%d currently_tainted_domains=%s tainted_tasks=%d correlation_tainted_tasks=%d tainted_processes=%d recovered_domains=%d unsequenced_records=%d ringbuf_reserve_fail=%d ringbuf_copy_fail=%d stats_available=%t; history recovery requires session end; totals cover observed events only\n",
		snapshot.StreamGaps, snapshot.EstimatedLost, snapshot.UnobservedTail, snapshot.SequenceReorders, snapshot.TaintTransitions,
		strings.Join(snapshot.Domains, ","), snapshot.TaintedTasks, snapshot.CorrelationTaintedTasks, snapshot.TaintedProcesses,
		snapshot.RecoveredDomains, snapshot.LegacyRecords, stats.RingbufReserveFail, stats.RingbufCopyFail, stats.Available)
}
