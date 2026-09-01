package main

import (
	"io"
	"sort"
)

type durationStat struct {
	total   uint64
	minimum uint64
	maximum uint64
}

func (stat *durationStat) record(duration uint64, first bool) {
	stat.total += duration
	if first || duration < stat.minimum {
		stat.minimum = duration
	}
	if duration > stat.maximum {
		stat.maximum = duration
	}
}

type syscallStat struct {
	calls  int
	errors int
	cpu    durationStat
	wall   durationStat
}

type SummaryStats struct {
	stats   map[string]*syscallStat
	order   []string
	options summaryOptions
}

// traceSummaryOwner is only the composition boundary for one shared summary state.
// Consumers receive traceSummaryRecorder or traceSummaryWriter separately.
type traceSummaryOwner interface {
	traceSummaryRecorder
	traceSummaryWriter
}

func newSummaryStats() *SummaryStats {
	return newConfiguredSummaryStats(defaultSummaryOptions())
}

func newConfiguredSummaryStats(options summaryOptions) *SummaryStats {
	options.columns = append([]summaryColumn(nil), options.columns...)
	if len(options.columns) == 0 {
		options = defaultSummaryOptions()
	}
	return &SummaryStats{options: options}
}

func (s *traceSession) summaryStats() traceSummaryOwner {
	if s == nil {
		return nil
	}
	return s.dependencies.Summary
}

func (st *SummaryStats) Record(name string, cpuDuration, wallDuration uint64, ret int64) {
	if st.stats == nil {
		st.stats = make(map[string]*syscallStat)
	}
	stat := st.stats[name]
	if stat == nil {
		stat = &syscallStat{}
		st.stats[name] = stat
		st.order = append(st.order, name)
	}
	first := stat.calls == 0
	stat.calls++
	stat.cpu.record(cpuDuration, first)
	stat.wall.record(wallDuration, first)
	if ret < 0 && ret >= -4095 {
		stat.errors++
	}
}

func (st *SummaryStats) Print(w io.Writer) {
	st.printTable(w)
}

type summaryStatEntry struct {
	name string
	stat *syscallStat
}

func (st *SummaryStats) sortedEntries() []summaryStatEntry {
	entries := make([]summaryStatEntry, 0, len(st.order))
	for _, name := range st.order {
		entries = append(entries, summaryStatEntry{name: name, stat: st.stats[name]})
	}
	if st.options.sortBy == summaryColumnNone {
		return entries
	}
	sort.SliceStable(entries, func(i, j int) bool { return st.entryLess(entries[i], entries[j]) })
	return entries
}

func (st *SummaryStats) totals() (int, int, uint64) {
	totalCalls := 0
	totalErrors := 0
	var totalDurationNs uint64
	for _, stat := range st.stats {
		totalCalls += stat.calls
		totalErrors += stat.errors
		totalDurationNs += st.primaryTiming(stat).total
	}
	return totalCalls, totalErrors, totalDurationNs
}
