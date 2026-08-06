package cli

import (
	"fmt"
	"strings"
)

const TraceAllFDs int32 = -1

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

func parseReadWriteFDSet(val string, dst map[int32]bool) bool {
	for fd := range dst {
		delete(dst, fd)
	}
	val = strings.TrimSpace(val)
	switch val {
	case "all", "!none":
		dst[TraceAllFDs] = true
		return false
	case "", "none", "!all":
		return false
	}
	negated := strings.HasPrefix(val, "!")
	if negated {
		val = strings.TrimPrefix(val, "!")
	}
	for _, s := range strings.Split(val, ",") {
		s = strings.TrimSpace(s)
		switch s {
		case "all":
			dst[TraceAllFDs] = true
			continue
		case "", "none":
			continue
		}
		var fd int32
		if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 {
			dst[fd] = true
		}
	}
	return negated
}
