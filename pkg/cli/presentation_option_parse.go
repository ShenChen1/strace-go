package cli

import (
	"strconv"
	"strings"
)

func applyShortRenderFlag(flag byte, opts *Options) bool {
	switch flag {
	case 'y':
		applyDecodeFDMode(opts, nextRepeatedMode(opts.ShowPathsMode, DecodeFDModeAll))
	case 'Y':
		parseDecodePIDs("comm", opts)
	case 't':
		opts.PrintTimeMode = nextRepeatedMode(opts.PrintTimeMode, 3)
	case 'r':
		opts.PrintRelativeTime = true
	case 'T':
		opts.PrintSyscallTime = true
	case 'k':
		opts.StackTrace = true
	case 'i':
		opts.InstructionPointer = true
	case 'n':
		opts.PrintSyscallNumber = true
	case 'N':
		opts.PrintArgNames = true
	case 'z':
		setSuccessfulOnly(opts)
	case 'Z':
		setFailedOnly(opts)
	case 'x':
		opts.HexEscapeMode = nextRepeatedMode(opts.HexEscapeMode, 2)
	case 'q':
		applyShortQuiet(opts)
	default:
		return false
	}
	return true
}

func nextRepeatedMode(current, maximum int) int {
	if current < maximum {
		return current + 1
	}
	return maximum
}

func parseDecodePIDs(value string, opts *Options) {
	inverted := false
	for strings.HasPrefix(value, "!") {
		inverted = !inverted
		value = strings.TrimPrefix(value, "!")
	}

	comm, pidns := false, false
	switch value {
	case "all":
		comm, pidns = true, true
	case "none":
	default:
		for _, token := range strings.Split(value, ",") {
			switch token {
			case "comm":
				comm = true
			case "pidns":
				pidns = true
			default:
				failOption("invalid decode-pids '%s'", token)
			}
		}
	}
	if inverted {
		comm, pidns = !comm, !pidns
	}
	opts.DecodePIDsComm = comm
	opts.DecodePIDsPIDNS = pidns
}

func parseColorMode(value string) string {
	switch value {
	case ColorModeAuto, ColorModeAlways, ColorModeNever:
		return value
	default:
		failOption("invalid --color argument: '%s'", value)
		return ""
	}
}

func parseTipsOption(value string, opts *Options) {
	if opts.TipsMode == "" {
		opts.TipsMode = TipsModeCompact
	}
	if value == "" {
		return
	}
	for _, rawToken := range strings.Split(value, ",") {
		token := strings.ToLower(rawToken)
		kind, selected, prefixed := strings.Cut(token, ":")
		if prefixed {
			switch kind {
			case "id":
				if applyTipsID(selected, opts) {
					continue
				}
			case "format":
				if applyTipsMode(selected, opts) {
					continue
				}
			}
		} else if applyTipsID(token, opts) || applyTipsMode(token, opts) {
			continue
		}
		failOption("invalid --tips argument: '%s'", value)
	}
}

func applyTipsID(value string, opts *Options) bool {
	if value == "random" {
		opts.TipsID = TipsIDRandom
		return true
	}
	id, err := strconv.ParseUint(value, 10, 31)
	if err != nil {
		return false
	}
	opts.TipsID = int(id)
	return true
}

func applyTipsMode(value string, opts *Options) bool {
	switch value {
	case TipsModeNone, TipsModeCompact, TipsModeFull:
		opts.TipsMode = value
		return true
	default:
		return false
	}
}
