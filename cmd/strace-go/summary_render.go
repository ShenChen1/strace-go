package main

import (
	"fmt"
	"io"
	"strconv"
)

type summaryTotals struct {
	calls  int
	errors int
	cpu    durationStat
	wall   durationStat
}

type summaryColumnLayout struct {
	column summaryColumn
	width  int
}

type summaryRow struct {
	name   string
	stat   *syscallStat
	totals summaryTotals
	total  bool
}

func (st *SummaryStats) printTable(w io.Writer) {
	if st == nil || w == nil {
		return
	}
	entries := st.sortedEntries()
	totals := st.summaryTotals()
	layout := st.columnLayout(entries, totals)
	printSummaryHeader(w, layout)
	printSummaryDivider(w, layout)
	for _, entry := range entries {
		st.printSummaryRow(w, layout, summaryRow{name: entry.name, stat: entry.stat, totals: totals})
	}
	printSummaryDivider(w, layout)
	st.printSummaryRow(w, layout, summaryRow{name: "total", totals: totals, total: true})
}

func (st *SummaryStats) summaryTotals() summaryTotals {
	totals := summaryTotals{}
	first := true
	for _, stat := range st.stats {
		totals.calls += stat.calls
		totals.errors += stat.errors
		mergeSummaryTiming(&totals.cpu, stat.cpu, first)
		mergeSummaryTiming(&totals.wall, stat.wall, first)
		first = false
	}
	return totals
}

func (st *SummaryStats) columnLayout(entries []summaryStatEntry, totals summaryTotals) []summaryColumnLayout {
	layout := make([]summaryColumnLayout, 0, len(st.options.columns))
	for _, column := range st.options.columns {
		width := summaryColumnBaseWidth(column)
		width = maxInt(width, st.summaryColumnDataWidth(column, totals))
		for _, entry := range entries {
			width = maxInt(width, st.summaryEntryColumnWidth(column, entry))
		}
		layout = append(layout, summaryColumnLayout{column: column, width: width})
	}
	return layout
}

func printSummaryHeader(w io.Writer, layout []summaryColumnLayout) {
	for index, item := range layout {
		if index > 0 {
			fmt.Fprint(w, " ")
		}
		lastName := index == len(layout)-1 && item.column == summaryColumnName
		if lastName {
			fmt.Fprint(w, summaryColumnHeader(item.column))
		} else if item.column == summaryColumnName {
			fmt.Fprintf(w, "%-*s", item.width, summaryColumnHeader(item.column))
		} else {
			fmt.Fprintf(w, "%*s", item.width, summaryColumnHeader(item.column))
		}
	}
	fmt.Fprintln(w)
}

func printSummaryDivider(w io.Writer, layout []summaryColumnLayout) {
	for index, item := range layout {
		if index > 0 {
			fmt.Fprint(w, " ")
		}
		for count := 0; count < item.width; count++ {
			fmt.Fprint(w, "-")
		}
	}
	fmt.Fprintln(w)
}

func (st *SummaryStats) printSummaryRow(w io.Writer, layout []summaryColumnLayout, row summaryRow) {
	for index, item := range layout {
		if index > 0 {
			fmt.Fprint(w, " ")
		}
		value := st.summaryCellValue(item.column, row)
		lastName := index == len(layout)-1 && item.column == summaryColumnName
		if lastName {
			fmt.Fprint(w, value)
		} else if item.column == summaryColumnName {
			fmt.Fprintf(w, "%-*s", item.width, value)
		} else {
			fmt.Fprintf(w, "%*s", item.width, value)
		}
	}
	fmt.Fprintln(w)
}

func (st *SummaryStats) summaryCellValue(column summaryColumn, row summaryRow) string {
	if column == summaryColumnName {
		return row.name
	}
	if row.total {
		return st.summaryTotalCellValue(column, row.totals)
	}
	if row.stat == nil {
		return ""
	}
	timing := st.timingForColumn(row.stat, column)
	switch column {
	case summaryColumnTimePercent:
		percent := 0.0
		totalTiming := row.totals.primaryTiming(st.options.wallClock)
		if totalTiming.total > 0 {
			percent = float64(timing.total) / float64(totalTiming.total) * 100
		}
		return fmt.Sprintf("%.2f", percent)
	case summaryColumnTotalTime, summaryColumnWallTotal:
		return formatSummarySeconds(timing.total)
	case summaryColumnMinTime, summaryColumnWallMin:
		return formatSummarySeconds(timing.minimum)
	case summaryColumnMaxTime, summaryColumnWallMax:
		return formatSummarySeconds(timing.maximum)
	case summaryColumnAvgTime, summaryColumnWallAvg:
		return strconv.FormatUint(summaryAverage(timing, row.stat.calls)/1000, 10)
	case summaryColumnCalls:
		return strconv.Itoa(row.stat.calls)
	case summaryColumnErrors:
		if row.stat.errors == 0 {
			return ""
		}
		return strconv.Itoa(row.stat.errors)
	default:
		return ""
	}
}

func (st *SummaryStats) summaryTotalCellValue(column summaryColumn, totals summaryTotals) string {
	timing := totals.timingForColumn(column, st.options.wallClock)
	switch column {
	case summaryColumnTimePercent:
		return "100.00"
	case summaryColumnTotalTime, summaryColumnWallTotal:
		return formatSummarySeconds(timing.total)
	case summaryColumnMinTime, summaryColumnWallMin:
		return formatSummarySeconds(timing.minimum)
	case summaryColumnMaxTime, summaryColumnWallMax:
		return formatSummarySeconds(timing.maximum)
	case summaryColumnAvgTime, summaryColumnWallAvg:
		if totals.calls == 0 {
			return "0"
		}
		return strconv.FormatUint(timing.total/uint64(totals.calls)/1000, 10)
	case summaryColumnCalls:
		return strconv.Itoa(totals.calls)
	case summaryColumnErrors:
		if totals.errors == 0 {
			return ""
		}
		return strconv.Itoa(totals.errors)
	default:
		return ""
	}
}

func summaryColumnHeader(column summaryColumn) string {
	switch column {
	case summaryColumnTimePercent:
		return "% time"
	case summaryColumnTotalTime:
		return "seconds"
	case summaryColumnMinTime:
		return "shortest"
	case summaryColumnMaxTime:
		return "longest"
	case summaryColumnAvgTime:
		return "usecs/call"
	case summaryColumnCalls:
		return "calls"
	case summaryColumnErrors:
		return "errors"
	case summaryColumnName:
		return "syscall"
	case summaryColumnWallTotal:
		return "wall-total"
	case summaryColumnWallMin:
		return "wall-min"
	case summaryColumnWallMax:
		return "wall-max"
	case summaryColumnWallAvg:
		return "wall-avg"
	default:
		return ""
	}
}

func summaryColumnBaseWidth(column summaryColumn) int {
	switch column {
	case summaryColumnTimePercent:
		return 6
	case summaryColumnTotalTime, summaryColumnAvgTime, summaryColumnWallTotal, summaryColumnWallAvg:
		return 11
	case summaryColumnCalls, summaryColumnErrors:
		return 9
	case summaryColumnName:
		return 16
	default:
		return len(summaryColumnHeader(column))
	}
}

func (st *SummaryStats) summaryColumnDataWidth(column summaryColumn, totals summaryTotals) int {
	return len(st.summaryTotalCellValue(column, totals))
}

func (st *SummaryStats) summaryEntryColumnWidth(column summaryColumn, entry summaryStatEntry) int {
	if column == summaryColumnName {
		return len(entry.name) + 1
	}
	totals := summaryTotals{calls: entry.stat.calls, cpu: entry.stat.cpu, wall: entry.stat.wall}
	return len(st.summaryCellValue(column, summaryRow{name: entry.name, stat: entry.stat, totals: totals}))
}

func mergeSummaryTiming(total *durationStat, timing durationStat, first bool) {
	total.total += timing.total
	if first || timing.minimum < total.minimum {
		total.minimum = timing.minimum
	}
	if timing.maximum > total.maximum {
		total.maximum = timing.maximum
	}
}

func (totals summaryTotals) primaryTiming(wallClock bool) durationStat {
	if wallClock {
		return totals.wall
	}
	return totals.cpu
}

func (totals summaryTotals) timingForColumn(column summaryColumn, wallClock bool) durationStat {
	if column == summaryColumnWallTotal || column == summaryColumnWallMin ||
		column == summaryColumnWallMax || column == summaryColumnWallAvg {
		return totals.wall
	}
	return totals.primaryTiming(wallClock)
}

func formatSummarySeconds(duration uint64) string {
	return fmt.Sprintf("%.6f", float64(duration)/1e9)
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
