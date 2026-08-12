package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
)

type syscallStat struct {
	calls    int
	errors   int
	duration uint64
}

type SummaryStats struct {
	stats map[string]*syscallStat
}

func newSummaryStats() *SummaryStats {
	return &SummaryStats{}
}

func (s *traceSession) summaryStats() *SummaryStats {
	if s == nil {
		return nil
	}
	return s.summary
}

func (st *SummaryStats) Record(name string, duration uint64, ret int64) {
	if st.stats == nil {
		st.stats = make(map[string]*syscallStat)
	}
	stat := st.stats[name]
	if stat == nil {
		stat = &syscallStat{}
		st.stats[name] = stat
	}
	stat.calls++
	stat.duration += duration
	if ret < 0 && ret >= -4095 {
		stat.errors++
	}
}

func (st *SummaryStats) Print(w io.Writer) {
	fmt.Fprintf(w, "%6s %11s %11s %9s %9s %s\n", "% time", "seconds", "usecs/call", "calls", "errors", "syscall")
	fmt.Fprintf(w, "------ ----------- ----------- --------- --------- ----------------\n")

	totalCalls, totalErrors, totalDurationNs := st.totals()
	for _, entry := range st.sortedEntries() {
		stat := entry.stat
		errStr := ""
		if stat.errors > 0 {
			errStr = strconv.Itoa(stat.errors)
		}
		pct := 0.0
		if totalDurationNs > 0 {
			pct = float64(stat.duration) / float64(totalDurationNs) * 100.0
		}
		secs := float64(stat.duration) / 1e9
		usecs := uint64(0)
		if stat.calls > 0 {
			usecs = stat.duration / uint64(stat.calls) / 1000
		}
		fmt.Fprintf(w, "%6.2f %11.6f %11d %9d %9s %s\n", pct, secs, usecs, stat.calls, errStr, entry.name)
	}

	fmt.Fprintf(w, "------ ----------- ----------- --------- --------- ----------------\n")
	errStr := ""
	if totalErrors > 0 {
		errStr = strconv.Itoa(totalErrors)
	}
	totalSecs := float64(totalDurationNs) / 1e9
	fmt.Fprintf(w, "%6.2f %11.6f %11s %9d %9s %s\n", 100.0, totalSecs, "", totalCalls, errStr, "total")
}

type summaryStatEntry struct {
	name string
	stat *syscallStat
}

func (st *SummaryStats) sortedEntries() []summaryStatEntry {
	entries := make([]summaryStatEntry, 0, len(st.stats))
	for name, stat := range st.stats {
		entries = append(entries, summaryStatEntry{name: name, stat: stat})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].stat.duration != entries[j].stat.duration {
			return entries[i].stat.duration > entries[j].stat.duration
		}
		if entries[i].stat.calls != entries[j].stat.calls {
			return entries[i].stat.calls > entries[j].stat.calls
		}
		return entries[i].name < entries[j].name
	})
	return entries
}

func (st *SummaryStats) totals() (int, int, uint64) {
	totalCalls := 0
	totalErrors := 0
	var totalDurationNs uint64
	for _, stat := range st.stats {
		totalCalls += stat.calls
		totalErrors += stat.errors
		totalDurationNs += stat.duration
	}
	return totalCalls, totalErrors, totalDurationNs
}
