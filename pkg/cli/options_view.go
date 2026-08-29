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

// VerboseDisabledFor reports whether a syscall should keep pointer structures opaque.
func (opts *Options) VerboseDisabledFor(syscallName string) bool {
	return opts != nil && !opts.VerboseDecodeFor(syscallName)
}

// NoAbbrevFor reports whether arrays and structures should be rendered in full.
func (opts *Options) NoAbbrevFor(syscallName string) bool {
	if opts == nil {
		return false
	}
	if opts.NoAbbrevConfigured {
		return opts.NoAbbrevSyscalls[syscallName]
	}
	return opts.Verbose
}

// VerboseDecodeFor reports whether pointer structures should be decoded.
func (opts *Options) VerboseDecodeFor(syscallName string) bool {
	if opts == nil {
		return false
	}
	if opts.VerboseConfigured {
		return opts.VerboseSyscalls[syscallName]
	}
	return !opts.VerboseDisabled[syscallName]
}

// RawSyscallFor reports whether all arguments should remain undecoded.
func (opts *Options) RawSyscallFor(syscallName string) bool {
	return opts != nil && opts.RawSyscalls[syscallName]
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

// ShowFDPathValue reports whether path details were selected.
func (opts *Options) ShowFDPathValue() bool {
	return opts.decodeFDDetailsValue()&DecodeFDDetailPath != 0
}

// ShowFDDeviceValue reports whether device details were selected.
func (opts *Options) ShowFDDeviceValue() bool {
	return opts.decodeFDDetailsValue()&DecodeFDDetailDevice != 0
}

// ShowFDSocketValue reports whether socket details were selected.
func (opts *Options) ShowFDSocketValue() bool {
	return opts.decodeFDDetailsValue()&DecodeFDDetailSocket != 0
}

func (opts *Options) decodeFDDetailsValue() uint32 {
	if opts == nil {
		return 0
	}
	if opts.DecodeFDDetails != 0 || opts.ShowPathsMode == DecodeFDModeNone {
		return opts.DecodeFDDetails
	}
	switch opts.ShowPathsMode {
	case DecodeFDModePath:
		return DecodeFDDetailPath
	case DecodeFDModeDevice:
		return DecodeFDDetailDevice
	case DecodeFDModeSocket:
		return DecodeFDDetailSocket
	case DecodeFDModeAll:
		return DecodeFDDetailsAll
	default:
		return 0
	}
}
