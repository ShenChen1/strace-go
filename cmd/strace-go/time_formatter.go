package main

import (
	"fmt"
	"time"

	"strace-go/pkg/cli"
)

type TimeFormatter struct {
	bootTimeOffsetNs  int64
	lastSyscallTimeNs uint64
	clock             traceClock
}

func newTimeFormatterWithClock(bootTimeOffsetNs int64, clock traceClock) *TimeFormatter {
	return &TimeFormatter{bootTimeOffsetNs: bootTimeOffsetNs, clock: clock}
}

func (s *traceSession) timeFormatterState() *TimeFormatter {
	if s == nil {
		return nil
	}
	return s.timeFormatter
}

// IMPACT: Prefix formats syscall time prefixes and owns relative-time state.
func (tf *TimeFormatter) Prefix(enterTimeMonoNs uint64, opts *cli.Options) string {
	if opts == nil || (opts.PrintTimeMode == 0 && !opts.PrintRelativeTime) {
		return ""
	}

	if opts.PrintRelativeTime {
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

	switch opts.PrintTimeMode {
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
	formatter := s.timeFormatterState()
	if formatter == nil {
		return ""
	}
	return formatter.Prefix(enterTimeMonoNs, s.opts)
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
