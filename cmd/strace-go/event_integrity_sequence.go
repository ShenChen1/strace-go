package main

const traceSequenceForwardLimit = uint64(1) << 63

// traceSequenceGapGroup keeps one forward jump compact even when uint64 wrap
// splits its missing interval. Confirmed groups survive an intentional stop
// because their detecting record also carried new producer-loss evidence.
type traceSequenceGapGroup struct {
	remaining      uint64
	detectedRecord uint64
	previousRecord uint64
	expected       uint64
	observed       uint64
	timestampNS    uint64
	pid            uint32
	tid            uint32
	cpu            uint32
	confirmed      bool
}

type traceSequenceGap struct {
	first uint64
	last  uint64
	group *traceSequenceGapGroup
}

type traceCPUSequence struct {
	sequence uint64
	record   uint64
	gaps     []traceSequenceGap
}

type traceSequenceObservation struct {
	expected       uint64
	previousRecord uint64
	gap            *traceSequenceGapGroup
	invalid        bool
}

func (i *TraceIntegrity) observeSequence(ev *traceEventEnvelope) traceSequenceObservation {
	state, seen := i.cpus[ev.cpu]
	expected := uint64(1)
	if seen {
		expected = state.sequence + 1
	}
	observation := traceSequenceObservation{expected: expected, previousRecord: state.record}
	if ev.seq == expected {
		state.sequence = ev.seq
		state.record = i.records
		i.cpus[ev.cpu] = state
		return observation
	}

	i.snapshot.Discontinuities++
	delta := ev.seq - expected
	if delta < traceSequenceForwardLimit {
		observation.gap = i.addSequenceGap(&state, ev, expected, delta)
		state.sequence = ev.seq
		state.record = i.records
		i.cpus[ev.cpu] = state
		return observation
	}

	i.snapshot.SequenceReorders++
	if i.resolveSequenceGap(&state, ev.seq) {
		i.cpus[ev.cpu] = state
		return observation
	}
	observation.invalid = true
	return observation
}

func (i *TraceIntegrity) addSequenceGap(
	state *traceCPUSequence,
	ev *traceEventEnvelope,
	expected uint64,
	delta uint64,
) *traceSequenceGapGroup {
	group := &traceSequenceGapGroup{
		remaining:      delta,
		detectedRecord: i.records,
		previousRecord: state.record,
		expected:       expected,
		observed:       ev.seq,
		timestampNS:    ev.integrityTimestamp(),
		pid:            ev.pid,
		tid:            ev.tid,
		cpu:            ev.cpu,
	}
	last := ev.seq - 1
	if expected <= last {
		state.gaps = append(state.gaps, traceSequenceGap{first: expected, last: last, group: group})
	} else {
		state.gaps = append(state.gaps,
			traceSequenceGap{first: expected, last: ^uint64(0), group: group},
			traceSequenceGap{first: 0, last: last, group: group},
		)
	}
	i.snapshot.StreamGaps++
	i.snapshot.EstimatedLost += delta
	i.snapshot.LostCount = delta
	return group
}

func (i *TraceIntegrity) resolveSequenceGap(state *traceCPUSequence, sequence uint64) bool {
	for index, gap := range state.gaps {
		if sequence < gap.first || sequence > gap.last {
			continue
		}
		i.removeSequenceFromGap(state, index, sequence)
		if gap.group == nil || gap.group.remaining == 0 {
			return true
		}
		gap.group.remaining--
		if i.snapshot.EstimatedLost != 0 {
			i.snapshot.EstimatedLost--
		}
		if gap.group.remaining == 0 && i.snapshot.StreamGaps != 0 {
			i.snapshot.StreamGaps--
		}
		return true
	}
	return false
}

func (i *TraceIntegrity) removeSequenceFromGap(state *traceCPUSequence, index int, sequence uint64) {
	gap := state.gaps[index]
	switch {
	case gap.first == gap.last:
		copy(state.gaps[index:], state.gaps[index+1:])
		state.gaps[len(state.gaps)-1] = traceSequenceGap{}
		state.gaps = state.gaps[:len(state.gaps)-1]
	case sequence == gap.first:
		state.gaps[index].first++
	case sequence == gap.last:
		state.gaps[index].last--
	default:
		state.gaps[index].last = sequence - 1
		state.gaps = append(state.gaps, traceSequenceGap{
			first: sequence + 1,
			last:  gap.last,
			group: gap.group,
		})
	}
}

func (i *TraceIntegrity) firstUnresolvedSequenceGap() *traceSequenceGapGroup {
	var first *traceSequenceGapGroup
	for _, state := range i.cpus {
		for _, gap := range state.gaps {
			if gap.group == nil || gap.group.remaining == 0 {
				continue
			}
			if first == nil || gap.group.detectedRecord < first.detectedRecord {
				first = gap.group
			}
		}
	}
	return first
}

func (i *TraceIntegrity) abandonUnconfirmedSequenceGaps() {
	discarded := make(map[*traceSequenceGapGroup]struct{})
	for cpu, state := range i.cpus {
		kept := state.gaps[:0]
		for _, gap := range state.gaps {
			if gap.group != nil && gap.group.confirmed {
				kept = append(kept, gap)
				continue
			}
			i.discardSequenceGapGroup(gap.group, discarded)
		}
		state.gaps = kept
		i.cpus[cpu] = state
	}
	i.snapshot.LostCount = i.detectedSequenceGapLostCount()
}

func (i *TraceIntegrity) discardSequenceGapGroup(group *traceSequenceGapGroup, discarded map[*traceSequenceGapGroup]struct{}) {
	if group == nil {
		return
	}
	if _, seen := discarded[group]; seen {
		return
	}
	discarded[group] = struct{}{}
	if i.snapshot.StreamGaps != 0 {
		i.snapshot.StreamGaps--
	}
	if group.remaining <= i.snapshot.EstimatedLost {
		i.snapshot.EstimatedLost -= group.remaining
	} else {
		i.snapshot.EstimatedLost = 0
	}
}

func (i *TraceIntegrity) detectedSequenceGapLostCount() uint64 {
	for _, state := range i.cpus {
		for _, gap := range state.gaps {
			if gap.group != nil && gap.group.detectedRecord == i.snapshot.DetectedAtRecord {
				return gap.group.remaining
			}
		}
	}
	return 0
}

func (i *TraceIntegrity) setSequenceLocation(ev *traceEventEnvelope, observation traceSequenceObservation) {
	i.snapshot.CPU = ev.cpu
	i.snapshot.ExpectedSequence = observation.expected
	i.snapshot.ObservedSequence = ev.seq
	i.snapshot.PreviousCPURecord = observation.previousRecord
	i.snapshot.PID, i.snapshot.TID = ev.pid, ev.tid
	i.snapshot.TimestampNS = ev.integrityTimestamp()
}

func (i *TraceIntegrity) setSequenceGapLocation(gap *traceSequenceGapGroup) {
	i.snapshot.CPU = gap.cpu
	i.snapshot.ExpectedSequence = gap.expected
	i.snapshot.ObservedSequence = gap.observed
	i.snapshot.PreviousCPURecord = gap.previousRecord
	i.snapshot.PID, i.snapshot.TID = gap.pid, gap.tid
	i.snapshot.TimestampNS = gap.timestampNS
	i.snapshot.DetectedAtRecord = gap.detectedRecord
	i.snapshot.LostCount = gap.remaining
}
