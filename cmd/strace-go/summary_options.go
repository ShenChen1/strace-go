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
	sortBy  summaryColumn
	columns []summaryColumn
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

func newSummaryOptions(sortBy string, columnNames []string) summaryOptions {
	options := defaultSummaryOptions()
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
		return left.stat.minimum > right.stat.minimum
	case summaryColumnMaxTime, summaryColumnWallMax:
		return left.stat.maximum > right.stat.maximum
	case summaryColumnAvgTime, summaryColumnWallAvg:
		return summaryAverage(left.stat) > summaryAverage(right.stat)
	default:
		return left.stat.duration > right.stat.duration
	}
}

func summaryAverage(stat *syscallStat) uint64 {
	if stat == nil || stat.calls == 0 {
		return 0
	}
	return stat.duration / uint64(stat.calls)
}
