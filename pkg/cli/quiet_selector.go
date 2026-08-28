package cli

import "strings"

type quietMessageSet uint8

const (
	quietMessageAttach quietMessageSet = 1 << iota
	quietMessageExit
	quietMessagePathResolution
	quietMessagePersonality
	quietMessageThreadExecve
	quietMessageAll = quietMessageAttach | quietMessageExit | quietMessagePathResolution |
		quietMessagePersonality | quietMessageThreadExecve
)

func parseQuietSet(value string, opts *Options) {
	if opts.quietLevel > 0 {
		failQuietModeConflict()
	}
	opts.quietSetConfigured = true
	applyQuietMessageSet(parseQuietMessageSet(value), opts)
}

func parseQuietMessageSet(value string) quietMessageSet {
	negated := strings.HasPrefix(value, "!")
	if negated {
		value = strings.TrimPrefix(value, "!")
	}
	var selected quietMessageSet
	if value != "" {
		for _, token := range strings.Split(value, ",") {
			selected |= quietMessageForToken(token)
		}
	}
	if negated {
		return quietMessageAll &^ selected
	}
	return selected
}

func quietMessageForToken(token string) quietMessageSet {
	switch token {
	case "none":
		return 0
	case "all":
		return quietMessageAll
	case "attach":
		return quietMessageAttach
	case "exit", "exits":
		return quietMessageExit
	case "path-resolution":
		return quietMessagePathResolution
	case "personality":
		return quietMessagePersonality
	case "thread-execve":
		return quietMessageThreadExecve
	default:
		failOption("invalid quiet '%s'", token)
		return 0
	}
}

func applyQuietMessageSet(selected quietMessageSet, opts *Options) {
	opts.QuietExit = selected&quietMessageExit != 0
	opts.QuietUnknownPid = selected&quietMessageAttach != 0
	opts.QuietThreadExecve = selected&quietMessageThreadExecve != 0
}

func failQuietModeConflict() {
	failOption("-q and -e quiet/--quiet cannot be provided simultaneously")
}
