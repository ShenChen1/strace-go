package main

import (
	"fmt"
	"time"
)

type TimeFormatter struct {
	bootTimeOffsetNs  int64
	lastSyscallTimeNs uint64
	clock             traceClock
}

func newTimeFormatterWithClock(bootTimeOffsetNs int64, clock traceClock) *TimeFormatter {
	return &TimeFormatter{bootTimeOffsetNs: bootTimeOffsetNs, clock: clock}
}

func (s *traceSession) timeFormatterState() traceTimeFormatter {
	if s == nil {
		return nil
	}
	return s.dependencies.TimeFormatter
}

// IMPACT: Prefix formats syscall time prefixes and owns relative-time state.
func (tf *TimeFormatter) Prefix(enterTimeMonoNs uint64, policy traceTimePolicy) string {
	if policy == nil {
		return ""
	}
	options := policy.TimeOptions()
	if options.absoluteFormat == "" && !options.printRelativeTime {
		return ""
	}

	absolutePrefix := ""
	if options.absoluteFormat != "" {
		realTimeNs := int64(enterTimeMonoNs) + tf.bootTimeOffsetNs
		absolutePrefix = formatAbsoluteTimestamp(realTimeNs, options.absoluteFormat, options.absolutePrecision)
	}
	if options.printRelativeTime {
		var diff uint64
		if tf.lastSyscallTimeNs != 0 {
			if enterTimeMonoNs >= tf.lastSyscallTimeNs {
				diff = enterTimeMonoNs - tf.lastSyscallTimeNs
			}
		}
		tf.lastSyscallTimeNs = enterTimeMonoNs
		relative := formatSeconds(diff, options.relativePrecision, 6)
		if absolutePrefix != "" {
			return absolutePrefix + " (+" + relative + ") "
		}
		return relative + " "
	}
	return absolutePrefix + " "
}

func formatSeconds(ns uint64, precision int, minimumWidth int) string {
	sec := ns / 1e9
	result := fmt.Sprintf("%*d", minimumWidth, sec)
	if precision == 0 {
		return result
	}
	fraction := (ns % 1e9) / precisionScale(precision)
	return fmt.Sprintf("%s.%0*d", result, precision, fraction)
}

func formatAbsoluteTimestamp(realTimeNs int64, format string, precision int) string {
	seconds := realTimeNs / 1e9
	base := fmt.Sprintf("%d", seconds)
	if format == "time" {
		base = time.Unix(0, realTimeNs).Format("15:04:05")
	}
	if precision == 0 {
		return base
	}
	fraction := uint64(realTimeNs % 1e9)
	return fmt.Sprintf("%s.%0*d", base, precision, fraction/precisionScale(precision))
}

func precisionScale(precision int) uint64 {
	switch precision {
	case 3:
		return 1_000_000
	case 6:
		return 1_000
	default:
		return 1
	}
}

func (s *traceSession) timePrefix(enterTimeMonoNs uint64) string {
	if s == nil || s.components == nil {
		return ""
	}
	formatter := s.timeFormatterState()
	if formatter == nil {
		return ""
	}
	return formatter.Prefix(enterTimeMonoNs, s.dependencies.OutputPolicy)
}

// NowMonoNs returns the current CLOCK_MONOTONIC value in nanoseconds so
// synthetic lines (e.g. the exit-status fallback) can be stamped with the
// correct real time instead of a zero mono timestamp.
func (tf *TimeFormatter) NowMonoNs() uint64 {
	if tf == nil || tf.clock == nil {
		return 0
	}
	return tf.clock.NowMonoNs()
}
