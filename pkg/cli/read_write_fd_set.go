package cli

import (
	"strconv"
	"strings"
)

const TraceAllFDs int32 = -1

const descriptorLeadingWhitespace = " \t\n\r\v\f"

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
	for fd := range dst {
		delete(dst, fd)
	}
	switch value {
	case "all", "!none":
		dst[TraceAllFDs] = true
		return false
	case "none", "!all":
		return false
	}
	original := value
	negated := strings.HasPrefix(value, "!")
	if negated {
		value = strings.TrimPrefix(value, "!")
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
		dst[fd] = true
		parsedAny = true
	}
	if !parsedAny {
		failOption("invalid descriptor '%s'", original)
	}
	return negated
}

func parseDescriptor(value string) (int32, bool) {
	normalized := strings.TrimLeft(value, descriptorLeadingWhitespace)
	parsed, err := strconv.ParseInt(normalized, 10, 32)
	if err != nil || parsed < 0 {
		return 0, false
	}
	return int32(parsed), true
}
