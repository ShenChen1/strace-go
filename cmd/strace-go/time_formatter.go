package main

import (
	"fmt"
	"time"

	"strace-go/pkg/cli"
)

type TimeFormatter struct {
	bootTimeOffsetNs  int64
	lastSyscallTimeNs uint64
}

func newTimeFormatter(bootTimeOffsetNs int64) *TimeFormatter {
	return &TimeFormatter{bootTimeOffsetNs: bootTimeOffsetNs}
}

func (s *traceSession) timeFormatterState() *TimeFormatter {
	if s.timeFormatter == nil {
		s.timeFormatter = newTimeFormatter(0)
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
			diff = enterTimeMonoNs - tf.lastSyscallTimeNs
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
	return s.timeFormatterState().Prefix(enterTimeMonoNs, s.opts)
}
