package handler

// FormattingOptions exposes scalar rendering policy without CLI ownership.
type FormattingOptions interface {
	StringLimitValue() int
	HexEscapeModeValue() int
	VerboseValue() bool
	VerboseDisabledFor(syscallName string) bool
	NoAbbrevFor(syscallName string) bool
	VerboseDecodeFor(syscallName string) bool
	RawSyscallFor(syscallName string) bool
}

// FDTraceOptions exposes path and buffer-dump policy without CLI maps.
type FDTraceOptions interface {
	ShowPathsValue() bool
	ShowPathsModeValue() int
	TraceReadFD(fd int32) bool
	TraceWriteFD(fd int32) bool
}

// OptionsPort is the read-only option capability used by syscall formatters.
type OptionsPort interface {
	FormattingOptions
	FDTraceOptions
}
