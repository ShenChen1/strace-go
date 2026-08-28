package main

import (
	"fmt"
	"io"
	"strconv"
)

type summaryTotals struct {
	calls    int
	errors   int
	duration uint64
	minimum  uint64
	maximum  uint64
}

type summaryColumnLayout struct {
	column summaryColumn
	width  int
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
		printSummaryRow(w, layout, entry.name, entry.stat, totals, false)
	}
	printSummaryDivider(w, layout)
	printSummaryRow(w, layout, "total", nil, totals, true)
}

func (st *SummaryStats) summaryTotals() summaryTotals {
	totals := summaryTotals{}
	first := true
	for _, stat := range st.stats {
		totals.calls += stat.calls
		totals.errors += stat.errors
		totals.duration += stat.duration
		if first || stat.minimum < totals.minimum {
			totals.minimum = stat.minimum
		}
		if stat.maximum > totals.maximum {
			totals.maximum = stat.maximum
		}
		first = false
	}
	return totals
}

func (st *SummaryStats) columnLayout(entries []summaryStatEntry, totals summaryTotals) []summaryColumnLayout {
	layout := make([]summaryColumnLayout, 0, len(st.options.columns))
	for _, column := range st.options.columns {
		width := summaryColumnBaseWidth(column)
		width = maxInt(width, summaryColumnDataWidth(column, totals))
		for _, entry := range entries {
			width = maxInt(width, summaryEntryColumnWidth(column, entry))
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

func printSummaryRow(w io.Writer, layout []summaryColumnLayout, name string, stat *syscallStat, totals summaryTotals, total bool) {
	for index, item := range layout {
		if index > 0 {
			fmt.Fprint(w, " ")
		}
		value := summaryCellValue(item.column, name, stat, totals, total)
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

func summaryCellValue(column summaryColumn, name string, stat *syscallStat, totals summaryTotals, total bool) string {
	if column == summaryColumnName {
		return name
	}
	if total {
		return summaryTotalCellValue(column, totals)
	}
	if stat == nil {
		return ""
	}
	switch column {
	case summaryColumnTimePercent:
		percent := 0.0
		if totals.duration > 0 {
			percent = float64(stat.duration) / float64(totals.duration) * 100
		}
		return fmt.Sprintf("%.2f", percent)
	case summaryColumnTotalTime, summaryColumnWallTotal:
		return formatSummarySeconds(stat.duration)
	case summaryColumnMinTime, summaryColumnWallMin:
		return formatSummarySeconds(stat.minimum)
	case summaryColumnMaxTime, summaryColumnWallMax:
		return formatSummarySeconds(stat.maximum)
	case summaryColumnAvgTime, summaryColumnWallAvg:
		return strconv.FormatUint(summaryAverage(stat)/1000, 10)
	case summaryColumnCalls:
		return strconv.Itoa(stat.calls)
	case summaryColumnErrors:
		if stat.errors == 0 {
			return ""
		}
		return strconv.Itoa(stat.errors)
	default:
		return ""
	}
}

func summaryTotalCellValue(column summaryColumn, totals summaryTotals) string {
	switch column {
	case summaryColumnTimePercent:
		return "100.00"
	case summaryColumnTotalTime, summaryColumnWallTotal:
		return formatSummarySeconds(totals.duration)
	case summaryColumnMinTime, summaryColumnWallMin:
		return formatSummarySeconds(totals.minimum)
	case summaryColumnMaxTime, summaryColumnWallMax:
		return formatSummarySeconds(totals.maximum)
	case summaryColumnAvgTime, summaryColumnWallAvg:
		if totals.calls == 0 {
			return "0"
		}
		return strconv.FormatUint(totals.duration/uint64(totals.calls)/1000, 10)
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

func summaryColumnDataWidth(column summaryColumn, totals summaryTotals) int {
	return len(summaryTotalCellValue(column, totals))
}

func summaryEntryColumnWidth(column summaryColumn, entry summaryStatEntry) int {
	if column == summaryColumnName {
		return len(entry.name) + 1
	}
	return len(summaryCellValue(column, entry.name, entry.stat, summaryTotals{duration: entry.stat.duration}, false))
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
