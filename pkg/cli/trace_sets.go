package cli

import (
	"strings"
)

var traceClassFlags = [...]struct {
	name string
	flag string
}{
	{name: "file", flag: "TF"},
	{name: "%file", flag: "TF"},
	{name: "process", flag: "TP"},
	{name: "%process", flag: "TP"},
	{name: "network", flag: "TN"},
	{name: "%network", flag: "TN"},
	{name: "%net", flag: "TN"},
	{name: "signal", flag: "TS"},
	{name: "%signal", flag: "TS"},
	{name: "ipc", flag: "TI"},
	{name: "%ipc", flag: "TI"},
	{name: "desc", flag: "TD"},
	{name: "%desc", flag: "TD"},
	{name: "memory", flag: "TM"},
	{name: "%memory", flag: "TM"},
	{name: "creds", flag: "TC"},
	{name: "%creds", flag: "TC"},
	{name: "stat", flag: "TST"},
	{name: "%stat", flag: "TST"},
	{name: "lstat", flag: "TLST"},
	{name: "%lstat", flag: "TLST"},
	{name: "fstat", flag: "TFST"},
	{name: "%fstat", flag: "TFST"},
	{name: "%%stat", flag: "TSTA"},
	{name: "statfs", flag: "TSF"},
	{name: "%statfs", flag: "TSF"},
	{name: "fstatfs", flag: "TFSF"},
	{name: "%fstatfs", flag: "TFSF"},
	{name: "%%statfs", flag: "TSFA"},
	{name: "pure", flag: "TPU"},
	{name: "%pure", flag: "TPU"},
	{name: "clock", flag: "TCL"},
	{name: "%clock", flag: "TCL"},
}

func traceClassFlag(s string) string {
	for _, class := range traceClassFlags {
		if class.name == s {
			return class.flag
		}
	}
	return ""
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
	case strings.HasPrefix(val, "fds="):
		parseTraceFDSet(strings.TrimPrefix(val, "fds="), opts)
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
	case strings.HasPrefix(val, "decode-fd="):
		parseDecodeFDValue(strings.TrimPrefix(val, "decode-fd="), opts)
	case strings.HasPrefix(val, "decode-pids="):
		parseDecodePIDs(strings.TrimPrefix(val, "decode-pids="), opts)
	case strings.HasPrefix(val, "decode-pid="):
		parseDecodePIDs(strings.TrimPrefix(val, "decode-pid="), opts)
	case strings.HasPrefix(val, "namespace="):
		parseNamespaceSet(strings.TrimPrefix(val, "namespace="), opts)
	case strings.HasPrefix(val, "inject="), strings.HasPrefix(val, "fault="):
		name, value, _ := strings.Cut(val, "=")
		rejectTamperingSelector("-e "+name, value)
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

func parseNamespaceSet(value string, opts *Options) {
	if value != "new" {
		failOption("invalid -e namespace= argument: '%s'", value)
	}
	opts.NamespaceNew = true
}

func rejectTamperingSelector(option, value string) {
	selector, _, _ := strings.Cut(value, ":")
	parseSyscallSelector(selector)
	rejectArchitectureConflict(option, "pure eBPF tracing cannot modify tracee state")
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
	allStatuses := [...]string{"successful", "failed", "unfinished", "unavailable", "detached"}
	inverted := false
	for strings.HasPrefix(val, "!") {
		inverted = !inverted
		val = strings.TrimPrefix(val, "!")
	}
	selected := make(map[string]bool, len(allStatuses))
	switch val {
	case "all":
		for _, status := range allStatuses {
			selected[status] = true
		}
	case "none":
	default:
		for _, token := range strings.Split(val, ",") {
			valid := false
			for _, status := range allStatuses {
				if token == status {
					valid = true
					selected[token] = true
					break
				}
			}
			if !valid {
				failOption("invalid status '%s'", token)
			}
		}
	}
	if inverted {
		complement := make(map[string]bool, len(allStatuses)-len(selected))
		for _, status := range allStatuses {
			if !selected[status] {
				complement[status] = true
			}
		}
		selected = complement
	}
	opts.TraceStatus = selected
	opts.StatusConfigured = true
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

func parseTraceFDSet(value string, opts *Options) {
	parsed := parseDescriptorSet(value)
	opts.TraceFDs = parsed.fds
	opts.TraceFDsConfigured = true
	opts.TraceFDsNegated = parsed.negated
}
