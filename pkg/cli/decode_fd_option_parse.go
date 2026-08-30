package cli

import "strings"

func parseDecodeFDValue(value string, opts *Options) {
	if value == "" {
		failOption("invalid decode-fds ''")
	}
	negated := strings.HasPrefix(value, "!")
	selector := strings.TrimPrefix(value, "!")
	details := uint32(0)
	if negated {
		details = DecodeFDDetailsAll
	}
	for _, token := range strings.Split(selector, ",") {
		bit := decodeFDDetailBit(token)
		if negated {
			details &^= bit
		} else {
			details |= bit
		}
	}
	applyDecodeFDDetails(opts, details)
}

func applyDecodeFDMode(opts *Options, mode int) {
	details := uint32(0)
	switch mode {
	case DecodeFDModePath:
		details = DecodeFDDetailPath
	case DecodeFDModeDevice:
		details = DecodeFDDetailDevice
	case DecodeFDModeSocket:
		details = DecodeFDDetailSocket
	case DecodeFDModeAll:
		details = DecodeFDDetailsAll
	}
	opts.DecodeFDDetails = details
	opts.ShowPathsMode = mode
	opts.ShowPaths = details != 0
}

func applyDecodeFDDetails(opts *Options, details uint32) {
	mode := DecodeFDModeSelected
	switch details {
	case 0:
		mode = DecodeFDModeNone
	case DecodeFDDetailPath:
		mode = DecodeFDModePath
	case DecodeFDDetailDevice:
		mode = DecodeFDModeDevice
	case DecodeFDDetailSocket:
		mode = DecodeFDModeSocket
	case DecodeFDDetailsAll:
		mode = DecodeFDModeAll
	}
	opts.DecodeFDDetails = details
	opts.ShowPathsMode = mode
	opts.ShowPaths = details != 0
}

func decodeFDDetailBit(value string) uint32 {
	switch value {
	case "none":
		return 0
	case "all":
		return DecodeFDDetailsAll
	case "path":
		return DecodeFDDetailPath
	case "dev":
		return DecodeFDDetailDevice
	case "socket":
		return DecodeFDDetailSocket
	case "eventfd":
		return DecodeFDDetailEventFD
	case "pidfd":
		return DecodeFDDetailPIDFD
	case "signalfd":
		return DecodeFDDetailSignalFD
	default:
		failOption("invalid decode-fds '%s'", value)
	}
	return 0
}
