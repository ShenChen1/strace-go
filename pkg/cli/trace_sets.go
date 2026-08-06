package cli

import (
	"fmt"
	"regexp"
	"strings"

	"strace-go/pkg/meta"
)

func addSyscallTrace(opts *Options, s string) {
	if strings.HasPrefix(s, "/") {
		pattern := strings.TrimPrefix(s, "/")
		if r, err := regexp.Compile(pattern); err == nil {
			opts.TraceSyscallRegexps = append(opts.TraceSyscallRegexps, r)
		}
		return
	}

	if classFlag := traceClassFlag(s); classFlag != "" {
		addTraceClass(opts, classFlag)
		return
	}

	opts.TraceSyscalls[s] = true
	addTraceAliases(opts, s)
}

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

func addTraceClass(opts *Options, classFlag string) {
	for _, sc := range meta.SyscallTable {
		flags := strings.Split(sc.Flags, "|")
		for _, f := range flags {
			if f == classFlag {
				opts.TraceSyscalls[sc.Name] = true
				break
			}
		}
	}
}

func addTraceAliases(opts *Options, s string) {
	switch s {
	case "access":
		opts.TraceSyscalls["faccessat"] = true
		opts.TraceSyscalls["faccessat2"] = true
	case "stat", "lstat":
		opts.TraceSyscalls["newfstatat"] = true
	case "chmod":
		opts.TraceSyscalls["chmodat"] = true
	case "mkdir":
		opts.TraceSyscalls["mkdirat"] = true
	case "rename":
		opts.TraceSyscalls["renameat"] = true
		opts.TraceSyscalls["renameat2"] = true
	case "chdir":
		opts.TraceSyscalls["fchdir"] = true
	case "chown":
		opts.TraceSyscalls["fchown"] = true
		opts.TraceSyscalls["lchown"] = true
		opts.TraceSyscalls["fchownat"] = true
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
	case strings.HasPrefix(val, "signal="):
		return
	case strings.HasPrefix(val, "quiet="):
		parseQuietSet(strings.TrimPrefix(val, "quiet="), opts)
	default:
		parseTraceSet(val, opts)
	}
}

func parseTraceSet(val string, opts *Options) {
	if strings.HasPrefix(val, "!") {
		opts.TraceSetIsNegated = true
		val = strings.TrimPrefix(val, "!")
	}
	for _, s := range strings.Split(val, ",") {
		addSyscallTrace(opts, s)
	}
}

func parseStatusSet(val string, opts *Options) {
	for _, s := range strings.Split(val, ",") {
		opts.TraceStatus[s] = true
	}
}

func parseQuietSet(val string, opts *Options) {
	for _, s := range strings.Split(val, ",") {
		if s == "exit" {
			opts.QuietExit = true
		}
		if s == "all" {
			opts.QuietUnknownPid = true
			opts.QuietThreadExecve = true
		}
	}
}

func parseVerboseSet(val string, opts *Options) {
	if strings.HasPrefix(val, "!") {
		for _, s := range strings.Split(strings.TrimPrefix(val, "!"), ",") {
			if s != "" {
				opts.VerboseDisabled[s] = true
			}
		}
		return
	}
	for _, s := range strings.Split(val, ",") {
		delete(opts.VerboseDisabled, s)
	}
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
