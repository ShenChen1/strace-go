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

const (
	ColorModeAuto   = "auto"
	ColorModeAlways = "always"
	ColorModeNever  = "never"
)

const (
	TipsModeNone    = "none"
	TipsModeCompact = "compact"
	TipsModeFull    = "full"
	TipsIDRandom    = -1
)

const (
	DecodeFDModeNone = iota
	DecodeFDModePath
	DecodeFDModeAll
	DecodeFDModeDevice
	DecodeFDModeSocket
	DecodeFDModeSelected
)

const (
	DecodeFDDetailPath uint32 = 1 << iota
	DecodeFDDetailDevice
	DecodeFDDetailEventFD
	DecodeFDDetailPIDFD
	DecodeFDDetailSocket
	DecodeFDDetailSignalFD
	DecodeFDDetailsAll = DecodeFDDetailPath | DecodeFDDetailDevice | DecodeFDDetailEventFD |
		DecodeFDDetailPIDFD | DecodeFDDetailSocket | DecodeFDDetailSignalFD
)

const hexEscapeModeNonASCIIChars = 3

// Options holds all parsed command-line options.
type Options struct {
	CmdArgs               []string
	Argv0                 string
	Argv0Set              bool
	RunAsUser             string
	AttachPids            []int
	EventFormat           string
	DebugEvents           bool
	DebugPhases           bool
	RuntimeDebug          bool
	ColorMode             string
	TipsMode              string
	TipsID                int
	OutFile               string
	AlignCol              int
	StringLimit           int
	HexEscapeMode         int // 0 = default, 1 = hex non-ascii (-x), 2 = hex all (-xx), 3 = hex escaped chars
	TraceSyscalls         map[string]bool
	TracePaths            map[string]bool
	TraceSyscallRegexps   []*regexp.Regexp
	TraceConfigured       bool
	TraceMatchesAll       bool
	TraceSetIsNegated     bool
	TraceFDs              map[int32]bool
	TraceFDsConfigured    bool
	TraceFDsNegated       bool
	TraceReadFDs          map[int32]bool
	TraceReadFDsNegated   bool
	TraceWriteFDs         map[int32]bool
	TraceWriteFDsNegated  bool
	TraceStatus           map[string]bool
	StatusConfigured      bool
	TraceSignals          map[int]bool
	SignalConfigured      bool
	SignalMatchesAll      bool
	SignalSetIsNegated    bool
	VerboseDisabled       map[string]bool
	RawSyscalls           map[string]bool
	NoAbbrevSyscalls      map[string]bool
	NoAbbrevConfigured    bool
	VerboseSyscalls       map[string]bool
	VerboseConfigured     bool
	ShowPaths             bool
	ShowPathsMode         int
	DecodeFDDetails       uint32
	Verbose               bool
	HelpRequested         bool
	VersionLevel          int
	SummaryOnly           bool
	SummaryAndPrint       bool
	SummarySortBy         string
	SummaryColumns        []string
	SummaryColumnsSet     bool
	QuietExit             bool
	QuietUnknownPid       bool
	QuietThreadExecve     bool
	FollowForks           bool
	OutputSeparate        bool
	XlatFormat            string   // "raw", "abbrev", "verbose"
	PrintTimeMode         int      // 0 = none, 1 = -t (HH:MM:SS), 2 = -tt (HH:MM:SS.UUUUUU), 3 = -ttt (UNIX.UUUUUU)
	PrintRelativeTime     bool     // -r
	PrintSyscallTime      bool     // -T
	AbsoluteTimeFormat    string   // --absolute-timestamps format: time, unix, none
	AbsoluteTimePrecision string   // --absolute-timestamps precision: s, ms, us, ns
	RelativeTimePrecision string   // --relative-timestamps precision: s, ms, us, ns
	SyscallTimePrecision  string   // --syscall-times precision: s, ms, us, ns
	PrintSyscallNumber    bool     // -n
	InstructionPointer    bool     // -i
	NamespaceNew          bool     // -e namespace=new, --namespace=new
	PrintArgNames         bool     // -N
	AlwaysShowPID         bool     // --always-show-pid
	DecodePIDsComm        bool     // -Y, --decode-pids=comm
	DecodePIDsPIDNS       bool     // --decode-pids=pidns
	DetachOnExecve        bool     // -b execve, --detach-on=execve
	KillOnExit            bool     // --kill-on-exit
	SyscallLimit          uint64   // --syscall-limit; zero disables the limit
	StackTrace            bool     // -k, --stack-trace
	SuccessfulOnly        bool     // -z
	FailedOnly            bool     // -Z
	EnvActions            []string // -E
	OutAppendMode         bool
	WallTime              bool // -w
	quietLevel            int
	quietSetConfigured    bool
}

// IMPACT: ParseArgs parses strace-go command-line arguments and returns Options.
// It initializes defaults and loops through args calling specialized sub-parsers.
func ParseArgs(args []string) *Options {
	opts := &Options{
		AlignCol:         40,
		StringLimit:      32,
		HexEscapeMode:    0,
		EventFormat:      EventFormatText,
		ColorMode:        ColorModeAuto,
		TipsID:           TipsIDRandom,
		XlatFormat:       "abbrev",
		TraceSyscalls:    make(map[string]bool),
		TracePaths:       make(map[string]bool),
		TraceFDs:         make(map[int32]bool),
		TraceReadFDs:     make(map[int32]bool),
		TraceWriteFDs:    make(map[int32]bool),
		TraceStatus:      make(map[string]bool),
		TraceSignals:     make(map[int]bool),
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
	validateParsedOptions(opts)

	return opts
}
