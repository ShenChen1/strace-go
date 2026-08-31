package cli

import "strings"

var summaryOptionAliases = map[string]string{
	"time": "time-percent", "time_percent": "time-percent", "time-percent": "time-percent",
	"time_total": "total-time", "time-total": "total-time", "total_time": "total-time", "total-time": "total-time",
	"min_time": "min-time", "min-time": "min-time", "time_min": "min-time", "time-min": "min-time", "shortest": "min-time",
	"max_time": "max-time", "max-time": "max-time", "time_max": "max-time", "time-max": "max-time", "longest": "max-time",
	"avg_time": "avg-time", "avg-time": "avg-time", "time_avg": "avg-time", "time-avg": "avg-time",
	"calls": "calls", "count": "calls",
	"error": "errors", "errors": "errors",
	"name": "name", "syscall": "name", "syscall_name": "name", "syscall-name": "name",
	"wall_total": "wall-total", "wall-total": "wall-total", "total_wall": "wall-total", "total-wall": "wall-total",
	"wall_min": "wall-min", "wall-min": "wall-min", "min_wall": "wall-min", "min-wall": "wall-min",
	"wall_max": "wall-max", "wall-max": "wall-max", "max_wall": "wall-max", "max-wall": "wall-max",
	"wall_avg": "wall-avg", "wall-avg": "wall-avg", "avg_wall": "wall-avg", "avg-wall": "wall-avg",
}

func parseSummarySort(value string) string {
	if value == "none" || value == "nothing" {
		return "none"
	}
	canonical, ok := summaryOptionAliases[value]
	if !ok {
		failOption("invalid sortby: '%s'", value)
	}
	return canonical
}

func parseSummaryColumns(value string) []string {
	columns := make([]string, 0, 8)
	seen := make(map[string]bool)
	for _, token := range strings.Split(value, ",") {
		canonical, ok := summaryOptionAliases[token]
		if !ok {
			failOption("unknown column name: '%s'", token)
		}
		if seen[canonical] {
			failOption("call summary column has been provided more than once: '%s'", token)
		}
		seen[canonical] = true
		columns = append(columns, canonical)
	}
	if !seen["name"] {
		columns = append(columns, "name")
	}
	return columns
}

func validateParsedOptions(opts *Options) {
	if opts == nil || opts.HelpRequested || opts.VersionRequested {
		return
	}
	if opts.SummaryColumnsSet && !opts.SummaryOnly && !opts.SummaryAndPrint {
		failOption("-U/--summary-columns must be given with (-c/--summary-only or -C/--summary)")
	}
	if opts.OutputSeparate && (opts.SummaryOnly || opts.SummaryAndPrint) {
		failOption("(-c/--summary-only or -C/--summary) and -ff/--output-separately are mutually exclusive")
	}
	if opts.KillOnExit && len(opts.AttachPids) > 0 {
		failOption("--kill-on-exit and -p/--attach are mutually exclusive options")
	}
	if opts.InstructionPointer && opts.SummaryOnly {
		failOption("-i/--instruction-pointer has no effect with -c/--summary-only")
	}
}
