// Package handler provides a registry-based architecture for decoding syscall arguments.
package handler

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

const (
	// AtFdcwd is the magic file descriptor value for AT_FDCWD.
	AtFdcwd = -100
)

// Context encapsulates all data needed to decode a single syscall event.
type Context struct {
	Pid             int
	Tid             int
	TargetPid       int
	SysId           uint32
	SysName         string
	Args            [6]uint64
	Ret             int64
	ProbeRetEnter   int32
	ProbeRetExit    int32
	PayloadSections []PayloadSection

	ScMeta  meta.Syscall
	Decoder *event.Decoder
	Opts    *cli.Options
	FdMap   map[string]string
}

// SnapshotReader exposes memory bytes copied by BPF at the syscall probe site.
type SnapshotReader interface {
	Section(argIndex int, kind PayloadKind) (PayloadSection, bool)
}

// Section returns the first semantic BPF payload captured for a syscall argument.
func (ctx *Context) Section(argIndex int, kind PayloadKind) (PayloadSection, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == argIndex && section.Kind == kind {
			return section, true
		}
	}
	return PayloadSection{}, false
}

// IsArgReadSuccess checks if a specific enter-stage argument read was successful in BPF.
func (ctx *Context) IsArgReadSuccess(argIndex int) bool {
	if ctx.ProbeRetEnter >= 0 {
		return true
	}
	if ctx.ProbeRetEnter == -1 {
		return false
	}
	mask := -ctx.ProbeRetEnter - 1
	return (mask & (1 << argIndex)) == 0
}

// ArgProbeRet returns 0 if success, -1 if not probed, -2 if probed but failed.
func (ctx *Context) ArgProbeRet(argIndex int) int32 {
	if ctx.ProbeRetEnter >= 0 {
		return 0
	}
	if ctx.ProbeRetEnter == -1 {
		return -1
	}
	mask := -ctx.ProbeRetEnter - 1
	if (mask & (1 << argIndex)) != 0 {
		return -2
	}
	return 0
}

func boundedBpfStructData(bpfBuf []byte, size int) ([]byte, bool) {
	if len(bpfBuf) == 0 || size <= 0 {
		return nil, false
	}
	if len(bpfBuf) >= size {
		return bpfBuf[:size], true
	}
	return bpfBuf, true
}

// Result contains the formatted arguments and optional hex dump.
type Result struct {
	ArgParts            []string
	HexDumpStr          string
	ReturnDesc          string
	ShowEmptyReturnDesc bool
}

// Handler defines the interface for decoding specific syscalls.
type Handler interface {
	Handle(ctx *Context) Result
}

var (
	registry       = make(map[string]Handler)
	defaultHandler Handler
)

// Register registers a handler for a specific syscall name.
func Register(name string, h Handler) {
	registry[name] = h
}

// SetDefault sets the fallback handler for unregistered syscalls.
func SetDefault(h Handler) {
	defaultHandler = h
}

// Get returns the registered handler for the syscall, or the default handler.
func Get(name string) Handler {
	if h, ok := registry[name]; ok {
		return h
	}
	return defaultHandler
}

// GetDefault returns the default handler.
func GetDefault() Handler {
	return defaultHandler
}
