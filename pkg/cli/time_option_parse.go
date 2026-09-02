package cli

import "strings"

func parseTimePrecision(arg, value string) string {
	switch value {
	case "s", "ms", "us", "ns":
		return value
	default:
		failOptionWithHelp("invalid %s argument: '%s'", strings.SplitN(arg, "=", 2)[0], value)
		return ""
	}
}

func parseAbsoluteTimestamp(arg, value string, opts *Options) {
	if opts.AbsoluteTimeFormat == "" {
		opts.AbsoluteTimeFormat = "time"
		opts.AbsoluteTimePrecision = "s"
	}
	option := strings.SplitN(arg, "=", 2)[0]
	for _, token := range strings.Split(value, ",") {
		if !applyAbsoluteTimestampToken(token, opts) {
			failOptionWithHelp("invalid %s argument: '%s'", option, value)
			return
		}
	}
}

func applyAbsoluteTimestampToken(token string, opts *Options) bool {
	if token == "" {
		return true
	}
	key, value, qualified := strings.Cut(token, ":")
	if qualified {
		switch key {
		case "format":
			return setAbsoluteTimeFormat(value, opts)
		case "precision":
			return setAbsoluteTimePrecision(value, opts)
		default:
			return false
		}
	}
	return setAbsoluteTimeFormat(token, opts) || setAbsoluteTimePrecision(token, opts)
}

func setAbsoluteTimeFormat(value string, opts *Options) bool {
	switch value {
	case "time", "unix", "none":
		opts.AbsoluteTimeFormat = value
		return true
	default:
		return false
	}
}

func setAbsoluteTimePrecision(value string, opts *Options) bool {
	switch value {
	case "s", "ms", "us", "ns":
		opts.AbsoluteTimePrecision = value
		return true
	default:
		return false
	}
}
