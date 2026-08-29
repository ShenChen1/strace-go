package cli

import (
	"strconv"
	"strings"
)

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
