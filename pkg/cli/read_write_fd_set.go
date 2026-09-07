package cli

import (
	"strconv"
	"strings"
)

const TraceAllFDs int32 = -1

const descriptorLeadingWhitespace = " \t\n\r\v\f"

type descriptorSet struct {
	fds     map[int32]bool
	negated bool
}

// TraceReadFD reports whether read buffer dumps are enabled for fd.
func (opts *Options) TraceReadFD(fd int32) bool {
	if opts == nil {
		return false
	}
	if opts.TraceReadFDsNegated {
		return !opts.TraceReadFDs[TraceAllFDs] && !opts.TraceReadFDs[fd]
	}
	return opts.TraceReadFDs[TraceAllFDs] || opts.TraceReadFDs[fd]
}

// TraceWriteFD reports whether write buffer dumps are enabled for fd.
func (opts *Options) TraceWriteFD(fd int32) bool {
	if opts == nil {
		return false
	}
	if opts.TraceWriteFDsNegated {
		return !opts.TraceWriteFDs[TraceAllFDs] && !opts.TraceWriteFDs[fd]
	}
	return opts.TraceWriteFDs[TraceAllFDs] || opts.TraceWriteFDs[fd]
}

// IMPACT: parseReadWriteFDSet owns upstream-compatible descriptor validation
// for every read/write qualifier spelling.
func parseReadWriteFDSet(value string, dst map[int32]bool) bool {
	parsed := parseDescriptorSet(value)
	for fd := range dst {
		delete(dst, fd)
	}
	for fd := range parsed.fds {
		dst[fd] = true
	}
	return parsed.negated
}

func parseDescriptorSet(value string) descriptorSet {
	parsed := descriptorSet{fds: make(map[int32]bool)}
	original := value
	negations := 0
	for strings.HasPrefix(value, "!") {
		negations++
		value = strings.TrimPrefix(value, "!")
	}
	parsed.negated = negations%2 == 1
	if value == "all" {
		if !parsed.negated {
			parsed.fds[TraceAllFDs] = true
		}
		return parsed
	}
	if value == "none" {
		if parsed.negated {
			parsed.fds[TraceAllFDs] = true
			parsed.negated = false
		}
		return parsed
	}
	parsedAny := false
	for _, descriptor := range strings.Split(value, ",") {
		if descriptor == "" {
			continue
		}
		fd, valid := parseDescriptor(descriptor)
		if !valid {
			failOption("invalid descriptor '%s'", descriptor)
		}
		parsed.fds[fd] = true
		parsedAny = true
	}
	if !parsedAny {
		failOption("invalid descriptor '%s'", original)
	}
	return parsed
}

func parseDescriptor(value string) (int32, bool) {
	normalized := strings.TrimLeft(value, descriptorLeadingWhitespace)
	parsed, err := strconv.ParseInt(normalized, 10, 32)
	if err != nil || parsed < 0 {
		return 0, false
	}
	return int32(parsed), true
}
