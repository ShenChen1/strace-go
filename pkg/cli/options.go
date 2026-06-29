// Package cli parses command-line arguments for strace-go,
// supporting the same flags as the original strace.
package cli

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"strace-go/pkg/meta"
)

const (
	EventFormatText = "text"
	EventFormatJSON = "json"
)

// Options holds all parsed command-line options.
type Options struct {
	CmdArgs             []string
	AttachPids          []int
	EventFormat         string
	DebugEvents         bool
	OutFile             string
	AlignCol            int
	StringLimit         int
	HexEscapeMode       int // 0 = default, 1 = hex non-ascii (-x), 2 = hex all (-xx)
	TraceSyscalls       map[string]bool
	TracePaths          map[string]bool
	TraceSyscallRegexps []*regexp.Regexp
	TraceSetIsNegated   bool
	TraceFDs            map[int32]bool
	TraceFDsNegated     bool
	TraceReadFDs        map[int32]bool
	TraceWriteFDs       map[int32]bool
	TraceStatus         map[string]bool
	VerboseDisabled     map[string]bool
	ShowPaths           bool
	ShowPathsMode       int // 0 = none, 1 = -y, 2 = -yy
	Verbose             bool
	HelpRequested       bool
	VersionRequested    bool
	SummaryOnly         bool
	SummaryAndPrint     bool
	QuietExit           bool
	QuietUnknownPid     bool
	QuietThreadExecve   bool
	FollowForks         bool
	XlatFormat          string   // "raw", "abbrev", "verbose"
	PrintTimeMode       int      // 0 = none, 1 = -t (HH:MM:SS), 2 = -tt (HH:MM:SS.UUUUUU), 3 = -ttt (UNIX.UUUUUU)
	PrintRelativeTime   bool     // -r
	PrintSyscallTime    bool     // -T
	StackTrace          bool     // -k
	SuccessfulOnly      bool     // -z
	FailedOnly          bool     // -Z
	EnvActions          []string // -E
	OutAppendMode       bool
	WallTime            bool // -w
}

// IMPACT: ParseArgs parses strace-go command-line arguments and returns Options.
// It initializes defaults and loops through args calling specialized sub-parsers.
func ParseArgs(args []string) *Options {
	opts := &Options{
		AlignCol:        40,
		StringLimit:     32,
		HexEscapeMode:   0,
		EventFormat:     EventFormatText,
		XlatFormat:      "abbrev",
		TraceSyscalls:   make(map[string]bool),
		TracePaths:      make(map[string]bool),
		TraceFDs:        make(map[int32]bool),
		TraceReadFDs:    make(map[int32]bool),
		TraceWriteFDs:   make(map[int32]bool),
		TraceStatus:     make(map[string]bool),
		VerboseDisabled: make(map[string]bool),
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

	var classFlag string
	switch s {
	case "file", "%file":
		classFlag = "TF"
	case "process", "%process":
		classFlag = "TP"
	case "network", "%network":
		classFlag = "TN"
	case "signal", "%signal":
		classFlag = "TS"
	case "ipc", "%ipc":
		classFlag = "TI"
	case "desc", "%desc":
		classFlag = "TD"
	case "memory", "%memory":
		classFlag = "TM"
	case "creds", "%creds":
		classFlag = "TC"
	case "stat", "%stat":
		classFlag = "TST"
	case "lstat", "%lstat":
		classFlag = "TLST"
	case "pure", "%pure":
		classFlag = "TPU"
	}
	if classFlag != "" {
		for _, sc := range meta.SyscallTable {
			flags := strings.Split(sc.Flags, "|")
			for _, f := range flags {
				if f == classFlag {
					opts.TraceSyscalls[sc.Name] = true
					break
				}
			}
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
	case strings.HasPrefix(arg, "-ve") && len(arg) > 3:
		opts.Verbose = true
		parseEFlag(arg[3:], opts)
	case arg == "-A" || arg == "--output-append-mode":
		opts.OutAppendMode = true
	case arg == "-f":
		opts.FollowForks = true
	case arg == "-v" || arg == "--no-abbrev":
		opts.Verbose = true
	case arg == "-c":
		opts.SummaryOnly = true
	case arg == "-C":
		opts.SummaryAndPrint = true
	case arg == "-w" || arg == "--summary-wall-clock":
		opts.WallTime = true
	case arg == "-h" || arg == "--help":
		opts.HelpRequested = true
	case arg == "-V" || arg == "--version":
		opts.VersionRequested = true
	case arg == "-y":
		opts.ShowPaths = true
		if opts.ShowPathsMode == 1 {
			opts.ShowPathsMode = 2
		} else if opts.ShowPathsMode == 0 {
			opts.ShowPathsMode = 1
		}
	case arg == "-t":
		opts.PrintTimeMode = 1
	case arg == "-tt":
		opts.PrintTimeMode = 2
	case arg == "-ttt":
		opts.PrintTimeMode = 3
	case arg == "-r":
		opts.PrintRelativeTime = true
	case arg == "-T":
		opts.PrintSyscallTime = true
	case arg == "-k":
		opts.StackTrace = true
	case arg == "-z":
		opts.SuccessfulOnly = true
	case arg == "-Z":
		opts.FailedOnly = true
	case arg == "-yy":
		opts.ShowPaths = true
		opts.ShowPathsMode = 2
	case arg == "-x":
		if opts.HexEscapeMode == 1 {
			opts.HexEscapeMode = 2
		} else if opts.HexEscapeMode == 0 {
			opts.HexEscapeMode = 1
		}
	case arg == "-xx":
		opts.HexEscapeMode = 2
	case strings.HasPrefix(arg, "-v") && len(arg) > 2:
		opts.Verbose = true
	default:
		return false
	}
	return true
}

// IMPACT: parseTraceFlags parses long trace flags: --trace and --trace-path.
func parseTraceFlags(arg string, opts *Options) bool {
	if arg == "--mode" || strings.HasPrefix(arg, "--mode=") {
		fmt.Fprintf(os.Stderr, "%s: --mode has been removed; strace-go always uses pure eBPF tracing\n", os.Args[0])
		os.Exit(1)
		return true
	}
	if strings.HasPrefix(arg, "--event-format=") {
		opts.EventFormat = strings.TrimPrefix(arg, "--event-format=")
		validateEventFormat(opts.EventFormat)
		return true
	}
	if arg == "--debug-events" {
		opts.EventFormat = EventFormatJSON
		opts.DebugEvents = true
		return true
	}
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
	if strings.HasPrefix(arg, "--trace-fds=") {
		parseTraceFDSet(strings.TrimPrefix(arg, "--trace-fds="), opts)
		return true
	}
	if strings.HasPrefix(arg, "--trace-fd=") {
		parseTraceFDSet(strings.TrimPrefix(arg, "--trace-fd="), opts)
		return true
	}
	if strings.HasPrefix(arg, "--env=") {
		opts.EnvActions = append(opts.EnvActions, strings.TrimPrefix(arg, "--env="))
		return true
	}
	if strings.HasPrefix(arg, "--attach=") {
		val := strings.TrimPrefix(arg, "--attach=")
		for _, s := range strings.Split(val, ",") {
			pid, err := strconv.Atoi(s)
			if err != nil || pid <= 0 {
				fmt.Fprintf(os.Stderr, "%s: Invalid process id: '%s'\n", os.Args[0], s)
				os.Exit(1)
			}
			opts.AttachPids = append(opts.AttachPids, pid)
		}
		return true
	}
	return false
}

func validateEventFormat(format string) {
	switch format {
	case EventFormatText, EventFormatJSON:
		return
	default:
		fmt.Fprintf(os.Stderr, "%s: unsupported --event-format value '%s'\n", os.Args[0], format)
		os.Exit(1)
	}
}

// IMPACT: parseValueFlag parses flags that take additional arguments.
func parseValueFlag(args []string, i *int, opts *Options) bool {
	arg := args[*i]
	var val string
	foundVal := false
	flag := ""

	for _, f := range []string{"-e", "-o", "-a", "-s", "-P", "-X", "-p", "-E", "-b", "--detach-on="} {
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
	case "-p":
		for _, s := range strings.Split(val, ",") {
			pid, err := strconv.Atoi(s)
			if err != nil || pid <= 0 {
				fmt.Fprintf(os.Stderr, "%s: Invalid process id: '%s'\n", os.Args[0], s)
				os.Exit(1)
			}
			opts.AttachPids = append(opts.AttachPids, pid)
		}
	case "-e":
		parseEFlag(val, opts)
	case "-X":
		opts.XlatFormat = val
	case "-E":
		opts.EnvActions = append(opts.EnvActions, val)
	case "-b", "--detach-on=":
		if val != "execve" {
			fmt.Fprintf(os.Stderr, "%s: Syscall '%s' for -b isn't supported\n", os.Args[0], val)
			os.Exit(1)
		}
	}
}

// IMPACT: parseEFlag parses the -e flag parameter values.
func parseEFlag(val string, opts *Options) {
	if strings.HasPrefix(val, "trace=") {
		val = strings.TrimPrefix(val, "trace=")
	} else if strings.HasPrefix(val, "read=") {
		for _, s := range strings.Split(strings.TrimPrefix(val, "read="), ",") {
			var fd int32
			if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 {
				opts.TraceReadFDs[fd] = true
			}
		}
		return
	} else if strings.HasPrefix(val, "write=") {
		for _, s := range strings.Split(strings.TrimPrefix(val, "write="), ",") {
			var fd int32
			if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 {
				opts.TraceWriteFDs[fd] = true
			}
		}
		return
	} else if strings.HasPrefix(val, "trace-fds=") {
		parseTraceFDSet(strings.TrimPrefix(val, "trace-fds="), opts)
		return
	} else if strings.HasPrefix(val, "trace-fd=") {
		parseTraceFDSet(strings.TrimPrefix(val, "trace-fd="), opts)
		return
	} else if strings.HasPrefix(val, "fd=") {
		parseTraceFDSet(strings.TrimPrefix(val, "fd="), opts)
		return
	} else if strings.HasPrefix(val, "status=") {
		for _, s := range strings.Split(strings.TrimPrefix(val, "status="), ",") {
			opts.TraceStatus[s] = true
		}
		return
	} else if strings.HasPrefix(val, "verbose=") {
		parseVerboseSet(strings.TrimPrefix(val, "verbose="), opts)
		return
	} else if strings.HasPrefix(val, "signal=") {
		// parsed but not implemented yet
		return
	} else if strings.HasPrefix(val, "quiet=") {
		for _, s := range strings.Split(strings.TrimPrefix(val, "quiet="), ",") {
			if s == "exit" {
				opts.QuietExit = true
			}
			if s == "all" {
				opts.QuietUnknownPid = true
				opts.QuietThreadExecve = true
			}
		}
		return
	}
	if strings.HasPrefix(val, "!") {
		opts.TraceSetIsNegated = true
		val = strings.TrimPrefix(val, "!")
	}
	for _, s := range strings.Split(val, ",") {
		addSyscallTrace(opts, s)
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
	if strings.HasPrefix(val, "!") {
		opts.TraceFDsNegated = true
		val = strings.TrimPrefix(val, "!")
	} else {
		opts.TraceFDsNegated = false
	}
	opts.TraceFDs = make(map[int32]bool)
	for _, s := range strings.Split(val, ",") {
		var fd int32
		if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 {
			opts.TraceFDs[fd] = true
		}
	}
}
