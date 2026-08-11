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

	ScMeta      meta.Syscall
	Meta        *meta.Catalog
	Registry    *Registry
	Decoder     *event.Decoder
	Opts        *cli.Options
	FDStateView FDStateReader
	EventFDView EventFDStateReader
	Runtime     RuntimeServices
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

// Registry owns the handler and type-decoder choices for one trace session.
// It is configured before event processing and treated as read-only afterward.
type Registry struct {
	handlers        map[string]Handler
	defaultHandler  Handler
	pointerDecoders []pointerDecoderEntry
	structDecoders  []structDecoderEntry
}

// NewRegistry returns an isolated copy of the built-in handler catalog.
func NewRegistry() *Registry {
	return builtinRegistry.clone()
}

func (r *Registry) clone() *Registry {
	if r == nil {
		return &Registry{handlers: make(map[string]Handler)}
	}
	clone := &Registry{
		handlers:        make(map[string]Handler, len(r.handlers)),
		defaultHandler:  r.defaultHandler,
		pointerDecoders: append([]pointerDecoderEntry(nil), r.pointerDecoders...),
		structDecoders:  append([]structDecoderEntry(nil), r.structDecoders...),
	}
	for name, h := range r.handlers {
		clone.handlers[name] = h
	}
	return clone
}

// Register adds or replaces a syscall handler in this registry.
func (r *Registry) Register(name string, h Handler) {
	if r == nil || name == "" || h == nil {
		return
	}
	if r.handlers == nil {
		r.handlers = make(map[string]Handler)
	}
	r.handlers[name] = h
}

// SetDefault sets the fallback handler in this registry.
func (r *Registry) SetDefault(h Handler) {
	if r == nil {
		return
	}
	r.defaultHandler = h
}

// Resolve returns the named handler or this registry's fallback handler.
func (r *Registry) Resolve(name string) Handler {
	if r == nil {
		return nil
	}
	if h, ok := r.handlers[name]; ok {
		return h
	}
	return r.defaultHandler
}

// Default returns the registry's fallback handler.
func (r *Registry) Default() Handler {
	if r == nil {
		return nil
	}
	return r.defaultHandler
}

// Handle resolves and invokes one syscall handler.
func (r *Registry) Handle(name string, ctx *Context) Result {
	h := r.Resolve(name)
	if h == nil {
		return Result{}
	}
	return h.Handle(ctx)
}

func (ctx *Context) registry() *Registry {
	if ctx != nil && ctx.Registry != nil {
		return ctx.Registry
	}
	return builtinRegistry
}
