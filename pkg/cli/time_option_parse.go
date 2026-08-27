package cli

import "strings"

func parseTimePrecision(arg, value string) string {
	switch value {
	case "s", "ms", "us", "ns":
		return value
	default:
		failOption("invalid %s argument: '%s'", strings.SplitN(arg, "=", 2)[0], value)
		return ""
	}
}

func parseAbsoluteTimestamp(value string, opts *Options) {
	if opts.AbsoluteTimeFormat == "" {
		opts.AbsoluteTimeFormat = "time"
		opts.AbsoluteTimePrecision = "s"
	}
	for _, token := range strings.Split(value, ",") {
		if token == "" {
			continue
		}
		key, item, qualified := strings.Cut(token, ":")
		if qualified {
			applyQualifiedTimestampToken(key, item, token, opts)
			continue
		}
		if token == "time" || token == "unix" || token == "none" {
			setAbsoluteTimeFormat(token, opts)
		} else {
			opts.AbsoluteTimePrecision = parseTimePrecision("--absolute-timestamps", token)
		}
	}
}

func applyQualifiedTimestampToken(key, value, token string, opts *Options) {
	switch key {
	case "format":
		setAbsoluteTimeFormat(value, opts)
	case "precision":
		opts.AbsoluteTimePrecision = parseTimePrecision("--absolute-timestamps", value)
	default:
		failOption("invalid --absolute-timestamps argument: '%s'", token)
	}
}

func setAbsoluteTimeFormat(value string, opts *Options) {
	switch value {
	case "time", "unix", "none":
		opts.AbsoluteTimeFormat = value
	default:
		failOption("invalid --absolute-timestamps argument: '%s'", value)
	}
}
