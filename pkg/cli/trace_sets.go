package cli

import (
	"fmt"
	"strings"
)

func traceClassFlag(s string) string {
	switch s {
	case "file", "%file":
		return "TF"
	case "process", "%process":
		return "TP"
	case "network", "%network":
		return "TN"
	case "signal", "%signal":
		return "TS"
	case "ipc", "%ipc":
		return "TI"
	case "desc", "%desc":
		return "TD"
	case "memory", "%memory":
		return "TM"
	case "creds", "%creds":
		return "TC"
	case "stat", "%stat":
		return "TST"
	case "lstat", "%lstat":
		return "TLST"
	case "pure", "%pure":
		return "TPU"
	default:
		return ""
	}
}

func addTraceAliasesTo(names map[string]bool, s string) {
	switch s {
	case "access":
		names["faccessat"] = true
		names["faccessat2"] = true
	case "stat", "lstat":
		names["newfstatat"] = true
	case "chmod":
		names["chmodat"] = true
	case "mkdir":
		names["mkdirat"] = true
	case "rename":
		names["renameat"] = true
		names["renameat2"] = true
	case "chdir":
		names["fchdir"] = true
	case "chown":
		names["fchown"] = true
		names["lchown"] = true
		names["fchownat"] = true
	}
}

func parseEFlag(val string, opts *Options) {
	switch {
	case strings.HasPrefix(val, "trace="):
		parseTraceSet(strings.TrimPrefix(val, "trace="), opts)
	case strings.HasPrefix(val, "read="):
		opts.TraceReadFDsNegated = parseReadWriteFDSet(strings.TrimPrefix(val, "read="), opts.TraceReadFDs)
	case strings.HasPrefix(val, "write="):
		opts.TraceWriteFDsNegated = parseReadWriteFDSet(strings.TrimPrefix(val, "write="), opts.TraceWriteFDs)
	case strings.HasPrefix(val, "trace-fds="):
		parseTraceFDSet(strings.TrimPrefix(val, "trace-fds="), opts)
	case strings.HasPrefix(val, "trace-fd="):
		parseTraceFDSet(strings.TrimPrefix(val, "trace-fd="), opts)
	case strings.HasPrefix(val, "fd="):
		parseTraceFDSet(strings.TrimPrefix(val, "fd="), opts)
	case strings.HasPrefix(val, "status="):
		parseStatusSet(strings.TrimPrefix(val, "status="), opts)
	case strings.HasPrefix(val, "verbose="):
		parseVerboseSet(strings.TrimPrefix(val, "verbose="), opts)
	case strings.HasPrefix(val, "abbrev="):
		parseAbbrevSet(strings.TrimPrefix(val, "abbrev="), opts)
	case strings.HasPrefix(val, "raw="):
		parseRawSet(strings.TrimPrefix(val, "raw="), opts)
	case strings.HasPrefix(val, "decode-fds="):
		parseDecodeFDValue(strings.TrimPrefix(val, "decode-fds="), opts)
	case strings.HasPrefix(val, "inject="), strings.HasPrefix(val, "fault="):
		rejectArchitectureConflict("-e inject/fault", "pure eBPF tracing cannot modify tracee state")
	case strings.HasPrefix(val, "signal="):
		parseSignalSet(strings.TrimPrefix(val, "signal="), opts)
	case strings.HasPrefix(val, "quiet="):
		parseQuietSet(strings.TrimPrefix(val, "quiet="), opts)
	case strings.HasPrefix(val, "q="):
		parseQuietSet(strings.TrimPrefix(val, "q="), opts)
	case strings.HasPrefix(val, "silent="):
		parseQuietSet(strings.TrimPrefix(val, "silent="), opts)
	default:
		parseTraceSet(val, opts)
	}
}

func parseTraceSet(val string, opts *Options) {
	selector := parseSyscallSelector(val)
	opts.TraceConfigured = true
	opts.TraceSyscalls = selector.names
	opts.TraceSyscallRegexps = selector.regexps
	opts.TraceSetIsNegated = selector.negated
	opts.TraceMatchesAll = false
	if matchesAll, explicit := selector.explicitAllOrNone(); explicit {
		opts.TraceMatchesAll = matchesAll
		opts.TraceSyscalls = make(map[string]bool)
		opts.TraceSyscallRegexps = nil
		opts.TraceSetIsNegated = false
	}
}

func parseStatusSet(val string, opts *Options) {
	for _, s := range strings.Split(val, ",") {
		opts.TraceStatus[s] = true
	}
}

func parseVerboseSet(val string, opts *Options) {
	selected := materializeSyscallSelector(parseSyscallSelector(val))
	opts.VerboseConfigured = true
	opts.VerboseSyscalls = selected
	opts.VerboseDisabled = complementSyscallSet(selected)
}

func parseAbbrevSet(val string, opts *Options) {
	abbreviated := materializeSyscallSelector(parseSyscallSelector(val))
	opts.NoAbbrevConfigured = true
	opts.NoAbbrevSyscalls = complementSyscallSet(abbreviated)
}

func parseRawSet(val string, opts *Options) {
	opts.RawSyscalls = materializeSyscallSelector(parseSyscallSelector(val))
}

func parseTraceFDSet(val string, opts *Options) {
	opts.TraceFDsNegated = strings.HasPrefix(val, "!")
	if opts.TraceFDsNegated {
		val = strings.TrimPrefix(val, "!")
	}
	opts.TraceFDs = make(map[int32]bool)
	for _, s := range strings.Split(val, ",") {
		var fd int32
		if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 {
			opts.TraceFDs[fd] = true
		}
	}
}
