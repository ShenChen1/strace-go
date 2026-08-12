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
	if options.printTimeMode == 0 && !options.printRelativeTime {
		return ""
	}

	if options.printRelativeTime {
		var diff uint64
		if tf.lastSyscallTimeNs != 0 {
			if enterTimeMonoNs >= tf.lastSyscallTimeNs {
				diff = enterTimeMonoNs - tf.lastSyscallTimeNs
			}
		}
		tf.lastSyscallTimeNs = enterTimeMonoNs
		return formatSecondsUsec(diff)
	}

	realTimeNs := int64(enterTimeMonoNs) + tf.bootTimeOffsetNs
	t := time.Unix(0, realTimeNs)

	switch options.printTimeMode {
	case 3:
		sec := realTimeNs / 1e9
		usec := (realTimeNs % 1e9) / 1000
		return fmt.Sprintf("%d.%06d ", sec, usec)
	case 2:
		return t.Format("15:04:05.000000") + " "
	case 1:
		return t.Format("15:04:05") + " "
	default:
		return ""
	}
}

func formatSecondsUsec(ns uint64) string {
	sec := ns / 1e9
	usec := (ns % 1e9) / 1000
	return fmt.Sprintf("%6d.%06d ", sec, usec)
}

func (s *traceSession) timePrefix(enterTimeMonoNs uint64) string {
	if s == nil || s.components == nil {
		return ""
	}
	formatter := s.timeFormatterState()
	if formatter == nil {
		return ""
	}
	return formatter.Prefix(enterTimeMonoNs, s.components.outputPolicy)
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
