// Package cli parses command-line arguments for strace-go,
// supporting the same flags as the original strace.
package cli

import (
	"regexp"
	"strings"
)

const (
	EventFormatText    = "text"
	EventFormatJSON    = "json"
	EventFormatNone    = "none"
	EventFormatReader  = "reader"
	EventFormatHandler = "handler"
)

// Options holds all parsed command-line options.
type Options struct {
	CmdArgs               []string
	Argv0                 string
	Argv0Set              bool
	AttachPids            []int
	EventFormat           string
	DebugEvents           bool
	DebugPhases           bool
	OutFile               string
	AlignCol              int
	StringLimit           int
	HexEscapeMode         int // 0 = default, 1 = hex non-ascii (-x), 2 = hex all (-xx)
	TraceSyscalls         map[string]bool
	TracePaths            map[string]bool
	TraceSyscallRegexps   []*regexp.Regexp
	TraceConfigured       bool
	TraceMatchesAll       bool
	TraceSetIsNegated     bool
	TraceFDs              map[int32]bool
	TraceFDsNegated       bool
	TraceReadFDs          map[int32]bool
	TraceReadFDsNegated   bool
	TraceWriteFDs         map[int32]bool
	TraceWriteFDsNegated  bool
	TraceStatus           map[string]bool
	VerboseDisabled       map[string]bool
	RawSyscalls           map[string]bool
	NoAbbrevSyscalls      map[string]bool
	NoAbbrevConfigured    bool
	VerboseSyscalls       map[string]bool
	VerboseConfigured     bool
	ShowPaths             bool
	ShowPathsMode         int // 0 = none, 1 = -y, 2 = -yy
	Verbose               bool
	HelpRequested         bool
	VersionRequested      bool
	SummaryOnly           bool
	SummaryAndPrint       bool
	QuietExit             bool
	QuietUnknownPid       bool
	QuietThreadExecve     bool
	FollowForks           bool
	XlatFormat            string   // "raw", "abbrev", "verbose"
	PrintTimeMode         int      // 0 = none, 1 = -t (HH:MM:SS), 2 = -tt (HH:MM:SS.UUUUUU), 3 = -ttt (UNIX.UUUUUU)
	PrintRelativeTime     bool     // -r
	PrintSyscallTime      bool     // -T
	AbsoluteTimeFormat    string   // --absolute-timestamps format: time, unix, none
	AbsoluteTimePrecision string   // --absolute-timestamps precision: s, ms, us, ns
	RelativeTimePrecision string   // --relative-timestamps precision: s, ms, us, ns
	SyscallTimePrecision  string   // --syscall-times precision: s, ms, us, ns
	PrintSyscallNumber    bool     // -n
	PrintArgNames         bool     // -N
	AlwaysShowPID         bool     // --always-show-pid
	StackTrace            bool     // -k, --stack-trace
	SuccessfulOnly        bool     // -z
	FailedOnly            bool     // -Z
	EnvActions            []string // -E
	OutAppendMode         bool
	WallTime              bool // -w
	quietLevel            int
}

// IMPACT: ParseArgs parses strace-go command-line arguments and returns Options.
// It initializes defaults and loops through args calling specialized sub-parsers.
func ParseArgs(args []string) *Options {
	opts := &Options{
		AlignCol:         40,
		StringLimit:      32,
		HexEscapeMode:    0,
		EventFormat:      EventFormatText,
		XlatFormat:       "abbrev",
		TraceSyscalls:    make(map[string]bool),
		TracePaths:       make(map[string]bool),
		TraceFDs:         make(map[int32]bool),
		TraceReadFDs:     make(map[int32]bool),
		TraceWriteFDs:    make(map[int32]bool),
		TraceStatus:      make(map[string]bool),
		VerboseDisabled:  make(map[string]bool),
		RawSyscalls:      make(map[string]bool),
		NoAbbrevSyscalls: make(map[string]bool),
		VerboseSyscalls:  make(map[string]bool),
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			opts.CmdArgs = append([]string(nil), args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			opts.CmdArgs = args[i:]
			break
		}
		if strings.HasPrefix(arg, "--") {
			parseLongOption(args, &i, opts)
		} else {
			parseShortOptions(args, &i, opts)
		}
	}

	return opts
}
