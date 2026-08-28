package cli

import "strconv"

func parseSyscallLimit(value string) uint64 {
	limit, err := strconv.ParseUint(value, 10, 64)
	if err != nil || limit == 0 {
		failOption("invalid --syscall-limit argument: '%s'", value)
	}
	return limit
}
