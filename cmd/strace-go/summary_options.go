package main

type summaryColumn uint8

const (
	summaryColumnNone summaryColumn = iota
	summaryColumnTimePercent
	summaryColumnTotalTime
	summaryColumnMinTime
	summaryColumnMaxTime
	summaryColumnAvgTime
	summaryColumnCalls
	summaryColumnErrors
	summaryColumnName
	summaryColumnWallTotal
	summaryColumnWallMin
	summaryColumnWallMax
	summaryColumnWallAvg
)

type summaryOptions struct {
	sortBy    summaryColumn
	columns   []summaryColumn
	wallClock bool
}

func defaultSummaryOptions() summaryOptions {
	return summaryOptions{
		sortBy: summaryColumnTotalTime,
		columns: []summaryColumn{
			summaryColumnTimePercent,
			summaryColumnTotalTime,
			summaryColumnAvgTime,
			summaryColumnCalls,
			summaryColumnErrors,
			summaryColumnName,
		},
	}
}

func newSummaryOptions(sortBy string, columnNames []string, wallClock bool) summaryOptions {
	options := defaultSummaryOptions()
	options.wallClock = wallClock
	if sortBy != "" {
		options.sortBy = summaryColumnFromName(sortBy)
	}
	if len(columnNames) == 0 {
		return options
	}
	options.columns = make([]summaryColumn, 0, len(columnNames)+1)
	hasName := false
	for _, name := range columnNames {
		column := summaryColumnFromName(name)
		options.columns = append(options.columns, column)
		hasName = hasName || column == summaryColumnName
	}
	if !hasName {
		options.columns = append(options.columns, summaryColumnName)
	}
	return options
}

func summaryColumnFromName(name string) summaryColumn {
	switch name {
	case "time-percent":
		return summaryColumnTimePercent
	case "total-time":
		return summaryColumnTotalTime
	case "min-time":
		return summaryColumnMinTime
	case "max-time":
		return summaryColumnMaxTime
	case "avg-time":
		return summaryColumnAvgTime
	case "calls":
		return summaryColumnCalls
	case "errors":
		return summaryColumnErrors
	case "name":
		return summaryColumnName
	case "wall-total":
		return summaryColumnWallTotal
	case "wall-min":
		return summaryColumnWallMin
	case "wall-max":
		return summaryColumnWallMax
	case "wall-avg":
		return summaryColumnWallAvg
	default:
		return summaryColumnNone
	}
}

func (st *SummaryStats) entryLess(left, right summaryStatEntry) bool {
	switch st.options.sortBy {
	case summaryColumnName:
		return left.name < right.name
	case summaryColumnCalls:
		return left.stat.calls > right.stat.calls
	case summaryColumnErrors:
		return left.stat.errors > right.stat.errors
	case summaryColumnMinTime, summaryColumnWallMin:
		return st.timingForColumn(left.stat, st.options.sortBy).minimum > st.timingForColumn(right.stat, st.options.sortBy).minimum
	case summaryColumnMaxTime, summaryColumnWallMax:
		return st.timingForColumn(left.stat, st.options.sortBy).maximum > st.timingForColumn(right.stat, st.options.sortBy).maximum
	case summaryColumnAvgTime, summaryColumnWallAvg:
		return summaryAverage(st.timingForColumn(left.stat, st.options.sortBy), left.stat.calls) >
			summaryAverage(st.timingForColumn(right.stat, st.options.sortBy), right.stat.calls)
	default:
		return st.timingForColumn(left.stat, st.options.sortBy).total > st.timingForColumn(right.stat, st.options.sortBy).total
	}
}

func (st *SummaryStats) primaryTiming(stat *syscallStat) durationStat {
	if stat == nil {
		return durationStat{}
	}
	if st.options.wallClock {
		return stat.wall
	}
	return stat.cpu
}

func (st *SummaryStats) timingForColumn(stat *syscallStat, column summaryColumn) durationStat {
	if stat == nil {
		return durationStat{}
	}
	if column == summaryColumnWallTotal || column == summaryColumnWallMin ||
		column == summaryColumnWallMax || column == summaryColumnWallAvg {
		return stat.wall
	}
	return st.primaryTiming(stat)
}

func summaryAverage(timing durationStat, calls int) uint64 {
	if calls == 0 {
		return 0
	}
	return timing.total / uint64(calls)
}
