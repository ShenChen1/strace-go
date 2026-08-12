package cli

// StringLimitValue returns the configured formatter string limit.
func (opts *Options) StringLimitValue() int {
	if opts == nil {
		return 0
	}
	return opts.StringLimit
}

// HexEscapeModeValue returns the configured byte escaping mode.
func (opts *Options) HexEscapeModeValue() int {
	if opts == nil {
		return 0
	}
	return opts.HexEscapeMode
}

// VerboseValue reports whether verbose structure rendering is enabled.
func (opts *Options) VerboseValue() bool {
	return opts != nil && opts.Verbose
}

// VerboseDisabledFor reports whether a syscall is explicitly abbreviated.
func (opts *Options) VerboseDisabledFor(syscallName string) bool {
	return opts != nil && opts.VerboseDisabled[syscallName]
}

// ShowPathsValue reports whether fd path rendering is enabled.
func (opts *Options) ShowPathsValue() bool {
	return opts != nil && opts.ShowPaths
}

// ShowPathsModeValue returns the configured fd path detail level.
func (opts *Options) ShowPathsModeValue() int {
	if opts == nil {
		return 0
	}
	return opts.ShowPathsMode
}
