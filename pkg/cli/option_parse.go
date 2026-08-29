package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const maxStringLimit = 1<<30 - 1

// IMPACT: parseShortOptions expands one short-option cluster left to right.
// A value-taking option consumes the remainder of the cluster or the next argument.
func parseShortOptions(args []string, index *int, opts *Options) {
	arg := args[*index]
	cluster := arg[1:]
	for offset := 0; offset < len(cluster); offset++ {
		flag := cluster[offset]
		if shortOptionTakesValue(flag) {
			value := cluster[offset+1:]
			if value == "" {
				value = consumeOptionValue(args, index, "-"+string(flag))
			}
			applyValueOption("-"+string(flag), value, opts)
			return
		}
		applyShortBoolean(flag, opts)
	}
}

func shortOptionTakesValue(flag byte) bool {
	return strings.ContainsRune("eoasPXpEbIOSU", rune(flag))
}

func applyShortBoolean(flag byte, opts *Options) {
	if applyShortControlFlag(flag, opts) || applyShortRenderFlag(flag, opts) {
		return
	}
	failOption("unrecognized option '-%c'", flag)
}

func applyShortControlFlag(flag byte, opts *Options) bool {
	switch flag {
	case 'A':
		opts.OutAppendMode = true
	case 'f':
		if opts.FollowForks {
			opts.OutputSeparate = true
		}
		opts.FollowForks = true
	case 'v':
		setNoAbbrevAll(opts)
	case 'c':
		setSummaryOnly(opts)
	case 'C':
		setSummaryAndPrint(opts)
	case 'w':
		opts.WallTime = true
	case 'h':
		opts.HelpRequested = true
	case 'V':
		opts.VersionRequested = true
	default:
		return false
	}
	return true
}

func applyShortQuiet(opts *Options) {
	if opts.quietSetConfigured {
		failQuietModeConflict()
	}
	opts.quietLevel++
	selected := quietMessageAttach | quietMessagePersonality
	if opts.quietLevel >= 2 {
		selected |= quietMessageExit
	}
	if opts.quietLevel >= 3 {
		selected = quietMessageAll
	}
	applyQuietMessageSet(selected, opts)
}

type longOptionState struct {
	args           []string
	index          *int
	opts           *Options
	arg            string
	name           string
	inlineValue    string
	hasInlineValue bool
}

// IMPACT: parseLongOption normalizes one long option onto the same fields used
// by short flags. Domain parsers keep each option family explicit and bounded.
func parseLongOption(args []string, index *int, opts *Options) {
	arg := args[*index]
	name, inlineValue, hasInlineValue := splitLongOption(arg)
	state := &longOptionState{
		args:           args,
		index:          index,
		opts:           opts,
		arg:            arg,
		name:           name,
		inlineValue:    inlineValue,
		hasInlineValue: hasInlineValue,
	}
	if parseLongProjectOption(state) || parseLongTargetOption(state) ||
		parseLongControlOption(state) || parseLongRenderOption(state) ||
		parseLongValueOption(state) {
		return
	}
	failOption("unrecognized option '%s'", arg)
}

func parseLongProjectOption(state *longOptionState) bool {
	switch state.name {
	case "mode":
		failOption("--mode has been removed; strace-go always uses pure eBPF tracing")
	case "event-format":
		state.opts.EventFormat = requiredLongValue(state)
		validateEventFormat(state.opts.EventFormat)
	case "debug-events":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.EventFormat = EventFormatJSON
		state.opts.DebugEvents = true
	case "debug-phases":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.EventFormat = EventFormatJSON
		state.opts.DebugPhases = true
	default:
		return false
	}
	return true
}

func parseLongTargetOption(state *longOptionState) bool {
	switch state.name {
	case "trace":
		parseTraceSet(requiredLongValue(state), state.opts)
	case "trace-path":
		state.opts.TracePaths[requiredLongValue(state)] = true
	case "trace-fds", "trace-fd":
		parseTraceFDSet(requiredLongValue(state), state.opts)
	case "env":
		state.opts.EnvActions = append(state.opts.EnvActions, requiredLongValue(state))
	case "argv0":
		state.opts.Argv0 = requiredLongValue(state)
		state.opts.Argv0Set = true
	case "attach":
		parseAttachPIDs(requiredLongValue(state), state.opts)
	case "detach-on":
		applyValueOption("-b", requiredLongValue(state), state.opts)
	default:
		return false
	}
	return true
}

func parseLongControlOption(state *longOptionState) bool {
	switch state.name {
	case "output-append-mode":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.OutAppendMode = true
	case "follow-forks":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.FollowForks = true
	case "output-separately":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.OutputSeparate = true
	case "no-abbrev":
		rejectLongValue(state.arg, state.hasInlineValue)
		setNoAbbrevAll(state.opts)
	case "summary-only":
		rejectLongValue(state.arg, state.hasInlineValue)
		setSummaryOnly(state.opts)
	case "summary":
		rejectLongValue(state.arg, state.hasInlineValue)
		setSummaryAndPrint(state.opts)
	case "summary-wall-clock":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.WallTime = true
	case "tips":
		parseTipsOption(optionalLongValue(state.inlineValue, state.hasInlineValue, ""), state.opts)
	case "help":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.HelpRequested = true
	case "version":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.VersionRequested = true
	case "seccomp-bpf":
		rejectLongValue(state.arg, state.hasInlineValue)
		rejectArchitectureConflict("--seccomp-bpf", "syscall filtering already occurs in eBPF")
	default:
		return false
	}
	return true
}

func parseLongRenderOption(state *longOptionState) bool {
	switch state.name {
	case "color":
		state.opts.ColorMode = parseColorMode(optionalLongValue(state.inlineValue, state.hasInlineValue, ColorModeAuto))
	case "decode-fds":
		parseDecodeFDValue(optionalLongValue(state.inlineValue, state.hasInlineValue, "path"), state.opts)
	case "relative-timestamps":
		state.opts.RelativeTimePrecision = parseTimePrecision(state.arg, optionalLongValue(state.inlineValue, state.hasInlineValue, "us"))
		state.opts.PrintRelativeTime = true
	case "syscall-times":
		state.opts.SyscallTimePrecision = parseTimePrecision(state.arg, optionalLongValue(state.inlineValue, state.hasInlineValue, "us"))
		state.opts.PrintSyscallTime = true
	case "absolute-timestamps", "timestamps":
		parseAbsoluteTimestamp(optionalLongValue(state.inlineValue, state.hasInlineValue, "format:time"), state.opts)
	case "stack-trace":
		if state.hasInlineValue && state.inlineValue != "" {
			failOption("stack trace mode '%s' conflicts with the pure eBPF address-only contract", state.inlineValue)
		}
		state.opts.StackTrace = true
	case "syscall-number":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.PrintSyscallNumber = true
	case "arg-names":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.PrintArgNames = true
	case "always-show-pid":
		rejectLongValue(state.arg, state.hasInlineValue)
		state.opts.AlwaysShowPID = true
	case "successful-only":
		rejectLongValue(state.arg, state.hasInlineValue)
		setSuccessfulOnly(state.opts)
	case "failed-only":
		rejectLongValue(state.arg, state.hasInlineValue)
		setFailedOnly(state.opts)
	case "strings-in-hex":
		parseStringsInHex(state.arg, optionalLongValue(state.inlineValue, state.hasInlineValue, "non-ascii"), state.opts)
	default:
		return false
	}
	return true
}

func parseLongValueOption(state *longOptionState) bool {
	switch state.name {
	case "columns":
		applyValueOption("-a", requiredLongValue(state), state.opts)
	case "output":
		applyValueOption("-o", requiredLongValue(state), state.opts)
	case "string-limit":
		applyValueOption("-s", requiredLongValue(state), state.opts)
	case "const-print-style":
		applyValueOption("-X", requiredLongValue(state), state.opts)
	case "summary-sort-by":
		applyValueOption("-S", requiredLongValue(state), state.opts)
	case "summary-columns":
		applyValueOption("-U", requiredLongValue(state), state.opts)
	case "syscall-limit":
		state.opts.SyscallLimit = parseSyscallLimit(requiredLongValue(state))
	case "interruptible":
		requiredLongValue(state)
		rejectArchitectureConflict("-I/--interruptible", "it controls ptrace stop signal blocking")
	case "summary-syscall-overhead":
		requiredLongValue(state)
		rejectArchitectureConflict("-O/--summary-syscall-overhead", "there is no ptrace syscall-stop overhead")
	case "inject", "fault":
		requiredLongValue(state)
		rejectArchitectureConflict("--"+state.name, "pure eBPF tracing cannot modify tracee state")
	case "status", "signal", "read", "write", "verbose", "abbrev", "raw":
		parseEFlag(state.name+"="+requiredLongValue(state), state.opts)
	case "quiet":
		parseLongQuiet(optionalLongValue(state.inlineValue, state.hasInlineValue, "attach,personality"), state.opts)
	case "decode-pids":
		parseDecodePIDs(requiredLongValue(state), state.opts)
	default:
		return false
	}
	return true
}

func splitLongOption(arg string) (string, string, bool) {
	name, value, found := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
	return name, value, found
}

func requiredLongValue(state *longOptionState) string {
	if state.hasInlineValue {
		return state.inlineValue
	}
	return consumeOptionValue(state.args, state.index, state.arg)
}

func optionalLongValue(inlineValue string, hasInlineValue bool, defaultValue string) string {
	if hasInlineValue {
		return inlineValue
	}
	return defaultValue
}

func consumeOptionValue(args []string, index *int, option string) string {
	if *index+1 >= len(args) {
		failOption("option '%s' requires an argument", option)
		return ""
	}
	*index++
	return args[*index]
}

func rejectLongValue(arg string, hasInlineValue bool) {
	if hasInlineValue {
		failOption("option '%s' does not allow an argument", arg)
	}
}

func applyValueOption(flag, value string, opts *Options) {
	switch flag {
	case "-o":
		opts.OutFile = value
	case "-a":
		opts.AlignCol = parseBoundedInt(value, 1, int(^uint(0)>>1), "invalid -a argument")
	case "-s":
		opts.StringLimit = parseBoundedInt(value, 0, maxStringLimit, "invalid -s argument")
	case "-P":
		opts.TracePaths[value] = true
	case "-p":
		parseAttachPIDs(value, opts)
	case "-e":
		parseEFlag(value, opts)
	case "-X":
		validateXlatFormat(value)
		opts.XlatFormat = value
	case "-E":
		opts.EnvActions = append(opts.EnvActions, value)
	case "-b":
		if value != "execve" {
			failOption("Syscall '%s' for -b isn't supported", value)
		}
		opts.DetachOnExecve = true
	case "-I":
		rejectArchitectureConflict("-I/--interruptible", "it controls ptrace stop signal blocking")
	case "-O":
		rejectArchitectureConflict("-O/--summary-syscall-overhead", "there is no ptrace syscall-stop overhead")
	case "-S":
		opts.SummarySortBy = parseSummarySort(value)
	case "-U":
		opts.SummaryColumns = parseSummaryColumns(value)
		opts.SummaryColumnsSet = true
	}
}

func parseAttachPIDs(value string, opts *Options) {
	for _, item := range strings.Split(value, ",") {
		pid, err := strconv.Atoi(item)
		if err != nil || pid <= 0 {
			failOption("Invalid process id: '%s'", item)
		}
		opts.AttachPids = append(opts.AttachPids, pid)
	}
}

func parseBoundedInt(value string, minimum, maximum int, label string) int {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < int64(minimum) || parsed > int64(maximum) {
		failOption("%s: '%s'", label, value)
	}
	return int(parsed)
}

func validateXlatFormat(value string) {
	switch value {
	case "raw", "abbrev", "verbose":
		return
	default:
		failOption("invalid -X argument: '%s'", value)
	}
}

func validateEventFormat(format string) {
	switch format {
	case EventFormatText, EventFormatJSON, EventFormatNone, EventFormatReader, EventFormatHandler:
		return
	default:
		failOption("unsupported --event-format value '%s'", format)
	}
}

func parseDecodeFDValue(value string, opts *Options) {
	switch value {
	case "none":
		applyDecodeFDMode(opts, DecodeFDModeNone)
	case "path":
		applyDecodeFDMode(opts, DecodeFDModePath)
	case "dev":
		applyDecodeFDMode(opts, DecodeFDModeDevice)
	case "all":
		applyDecodeFDMode(opts, DecodeFDModeAll)
	default:
		failOption("decode-fds value '%s' is not implemented yet", value)
	}
}

func applyDecodeFDMode(opts *Options, mode int) {
	opts.ShowPathsMode = mode
	opts.ShowPaths = mode > 0
}

func parseStringsInHex(arg, value string, opts *Options) {
	switch value {
	case "non-ascii":
		opts.HexEscapeMode = 1
	case "non-ascii-chars":
		opts.HexEscapeMode = hexEscapeModeNonASCIIChars
	case "all":
		opts.HexEscapeMode = 2
	default:
		failOption("invalid %s argument: '%s'", strings.SplitN(arg, "=", 2)[0], value)
	}
}

func parseLongQuiet(value string, opts *Options) {
	parseQuietSet(value, opts)
}

func setSummaryOnly(opts *Options) {
	if opts.SummaryAndPrint {
		failOption("-c/--summary-only and -C/--summary are mutually exclusive")
	}
	opts.SummaryOnly = true
}

func setSummaryAndPrint(opts *Options) {
	if opts.SummaryOnly {
		failOption("-c/--summary-only and -C/--summary are mutually exclusive")
	}
	opts.SummaryAndPrint = true
}

func setSuccessfulOnly(opts *Options) {
	opts.SuccessfulOnly = true
	opts.FailedOnly = false
}

func setFailedOnly(opts *Options) {
	opts.FailedOnly = true
	opts.SuccessfulOnly = false
}

func setNoAbbrevAll(opts *Options) {
	opts.Verbose = true
	opts.NoAbbrevConfigured = false
	opts.NoAbbrevSyscalls = make(map[string]bool)
}

func failOption(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], fmt.Sprintf(format, args...))
	os.Exit(1)
}

func rejectArchitectureConflict(option, reason string) {
	failOption("option '%s' conflicts with pure eBPF tracing: %s", option, reason)
}
