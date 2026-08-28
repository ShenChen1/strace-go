package cli

import (
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maxLinuxSignal = 64

func parseSignalSet(value string, opts *Options) {
	negated := strings.HasPrefix(value, "!")
	if negated {
		value = strings.TrimPrefix(value, "!")
	}

	opts.SignalConfigured = true
	opts.TraceSignals = make(map[int]bool)
	opts.SignalMatchesAll = false
	opts.SignalSetIsNegated = negated
	if applyUniversalSignalSet(value, negated, opts) {
		return
	}

	for _, token := range strings.Split(value, ",") {
		signal, ok := parseSignalNumber(token)
		if !ok {
			failOption("invalid signal '%s'", token)
		}
		opts.TraceSignals[signal] = true
	}
}

func applyUniversalSignalSet(value string, negated bool, opts *Options) bool {
	if value != "" && value != "none" && value != "all" {
		return false
	}
	matchesAll := value == "all"
	if negated {
		matchesAll = !matchesAll
	}
	opts.SignalMatchesAll = matchesAll
	opts.SignalSetIsNegated = false
	return true
}

func parseSignalNumber(value string) (int, bool) {
	if number, err := strconv.Atoi(value); err == nil {
		return number, number > 0 && number <= maxLinuxSignal
	}
	name := strings.ToUpper(value)
	if !strings.HasPrefix(name, "SIG") {
		name = "SIG" + name
	}
	if number, ok := parseRealtimeSignal(name); ok {
		return number, true
	}
	number := int(unix.SignalNum(name))
	return number, number > 0 && number <= maxLinuxSignal
}

func parseRealtimeSignal(name string) (int, bool) {
	if name == "SIGRTMIN" {
		return 32, true
	}
	indexText, found := strings.CutPrefix(name, "SIGRT_")
	if !found {
		return 0, false
	}
	index, err := strconv.Atoi(indexText)
	number := 32 + index
	return number, err == nil && index >= 0 && number <= maxLinuxSignal
}
