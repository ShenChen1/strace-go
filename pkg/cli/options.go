// Package cli parses command-line arguments for strace-go,
// supporting the same flags as the original strace.
package cli

import (
	"fmt"
	"regexp"
	"strings"
)

// Options holds all parsed command-line options.
type Options struct {
	CmdArgs             []string
	OutFile             string
	AlignCol            int
	StringLimit         int
	HexEscapeMode       int // 0 = default, 1 = hex non-ascii (-x), 2 = hex all (-xx)
	TraceSyscalls       map[string]bool
	TracePaths          map[string]bool
	TraceReadFDs        map[int32]bool
	TraceWriteFDs       map[int32]bool
	ShowPaths           bool
	ShowPathsMode       int // 0 = none, 1 = -y, 2 = -yy
	Verbose             bool
	HelpRequested       bool
	VersionRequested    bool
	QuietExit           bool
	QuietUnknownPid     bool
	QuietThreadExecve   bool
	FollowForks         bool
	XlatFormat          string // "raw", "abbrev", "verbose"
	TraceSyscallRegexps []*regexp.Regexp
}

// IMPACT: ParseArgs parses strace-go command-line arguments and returns Options.
// It initializes defaults and loops through args calling specialized sub-parsers.
func ParseArgs(args []string) *Options {
	opts := &Options{
		AlignCol:      40,
		StringLimit:   32,
		HexEscapeMode: 0,
		XlatFormat:    "abbrev",
		TraceSyscalls: make(map[string]bool),
		TracePaths:    make(map[string]bool),
		TraceReadFDs:  make(map[int32]bool),
		TraceWriteFDs: make(map[int32]bool),
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			opts.CmdArgs = args[i:]
			break
		}

		if parseQuiet(arg, opts) {
			continue
		}
		if parseBasicFlags(arg, opts) {
			continue
		}
		if parseTraceFlags(arg, opts) {
			continue
		}
		if parseValueFlag(args, &i, opts) {
			continue
		}
	}
	return opts
}

// IMPACT: addSyscallTrace adds a syscall to the trace set, mapping aliases to actual names.
func addSyscallTrace(opts *Options, s string) {
	if strings.HasPrefix(s, "/") {
		pattern := strings.TrimPrefix(s, "/")
		if r, err := regexp.Compile(pattern); err == nil {
			opts.TraceSyscallRegexps = append(opts.TraceSyscallRegexps, r)
		}
		return
	}
	opts.TraceSyscalls[s] = true
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

// IMPACT: parseQuiet parses quiet flags like -q, -qq, -qqq, and --quiet.
func parseQuiet(arg string, opts *Options) bool {
	if arg == "-q" {
		return true
	}
	if arg == "-qq" {
		opts.QuietExit = true
		opts.QuietUnknownPid = true
		return true
	}
	if arg == "-qqq" {
		opts.QuietExit = true
		opts.QuietUnknownPid = true
		opts.QuietThreadExecve = true
		return true
	}
	if strings.HasPrefix(arg, "--quiet=") {
		val := strings.TrimPrefix(arg, "--quiet=")
		for _, item := range strings.Split(val, ",") {
			if item == "exit" || item == "all" {
				opts.QuietExit = true
			}
			if item == "all" {
				opts.QuietUnknownPid = true
			}
			if item == "thread-execve" || item == "all" {
				opts.QuietThreadExecve = true
			}
		}
		return true
	}
	return false
}

// IMPACT: parseBasicFlags parses boolean flags such as fork following, help, version and verbose.
func parseBasicFlags(arg string, opts *Options) bool {
	switch {
	case arg == "-f":
		opts.FollowForks = true
	case arg == "-h" || arg == "--help":
		opts.HelpRequested = true
	case arg == "-V" || arg == "--version":
		opts.VersionRequested = true
	case arg == "-y":
		opts.ShowPaths = true
		opts.ShowPathsMode = 1
	case arg == "-yy":
		opts.ShowPaths = true
		opts.ShowPathsMode = 2
	case arg == "-x":
		opts.HexEscapeMode = 1
	case arg == "-xx":
		opts.HexEscapeMode = 2
	case arg == "-v":
		opts.Verbose = true
	case strings.HasPrefix(arg, "-v") && len(arg) > 2:
		opts.Verbose = true
	default:
		return false
	}
	return true
}

// IMPACT: parseTraceFlags parses long trace flags: --trace and --trace-path.
func parseTraceFlags(arg string, opts *Options) bool {
	if strings.HasPrefix(arg, "--trace=") {
		val := strings.TrimPrefix(arg, "--trace=")
		for _, s := range strings.Split(val, ",") {
			addSyscallTrace(opts, s)
		}
		return true
	}
	if strings.HasPrefix(arg, "--trace-path=") {
		opts.TracePaths[strings.TrimPrefix(arg, "--trace-path=")] = true
		return true
	}
	return false
}

// IMPACT: parseValueFlag parses flags that take additional arguments.
func parseValueFlag(args []string, i *int, opts *Options) bool {
	arg := args[*i]
	var val string
	foundVal := false
	flag := ""

	for _, f := range []string{"-e", "-o", "-a", "-s", "-P", "-X"} {
		if strings.HasPrefix(arg, f) {
			flag = f
			if len(arg) > len(f) {
				val = arg[len(f):]
				foundVal = true
			}
			break
		}
	}

	if flag == "" {
		return false
	}

	if !foundVal && *i+1 < len(args) {
		*i++
		val = args[*i]
		foundVal = true
	}

	if foundVal {
		applyValueFlag(flag, val, opts)
	}
	return true
}

// IMPACT: applyValueFlag applies value-based flags to the configuration.
func applyValueFlag(flag string, val string, opts *Options) {
	switch flag {
	case "-o":
		opts.OutFile = val
	case "-a":
		fmt.Sscanf(val, "%d", &opts.AlignCol)
	case "-s":
		fmt.Sscanf(val, "%d", &opts.StringLimit)
	case "-P":
		opts.TracePaths[val] = true
	case "-e":
		parseEFlag(val, opts)
	case "-X":
		opts.XlatFormat = val
	}
}

// IMPACT: parseEFlag parses the -e flag parameter values.
func parseEFlag(val string, opts *Options) {
	if strings.HasPrefix(val, "trace=") {
		for _, s := range strings.Split(strings.TrimPrefix(val, "trace="), ",") {
			addSyscallTrace(opts, s)
		}
	} else if strings.HasPrefix(val, "read=") {
		for _, s := range strings.Split(strings.TrimPrefix(val, "read="), ",") {
			var fd int32
			if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 {
				opts.TraceReadFDs[fd] = true
			}
		}
	} else if strings.HasPrefix(val, "write=") {
		for _, s := range strings.Split(strings.TrimPrefix(val, "write="), ",") {
			var fd int32
			if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 {
				opts.TraceWriteFDs[fd] = true
			}
		}
	} else {
		for _, s := range strings.Split(val, ",") {
			addSyscallTrace(opts, s)
		}
	}
}
