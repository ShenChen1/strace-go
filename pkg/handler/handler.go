// Package handler provides a registry-based architecture for decoding syscall arguments.
package handler

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
	"strace-go/pkg/procmem"
)

// Context encapsulates all data needed to decode a single syscall event.
type Context struct {
	Pid           int
	Tid           int
	TargetPid     int
	SysId         uint32
	SysName       string
	Args          [6]uint64
	Ret           int64
	ProbeRetEnter int32
	ProbeRetExit  int32
	Ptr           uint64
	StrArgBuf     []byte
	RawStrArg     string

	ScMeta    meta.Syscall
	MemReader *procmem.Reader
	Decoder   *event.Decoder
	Opts      *cli.Options
	FdMap     map[string]string
}

// IsArgReadSuccess checks if a specific enter-stage argument read was successful in BPF.
func (ctx *Context) IsArgReadSuccess(argIndex int) bool {
	if ctx.ProbeRetEnter >= 0 { return true }
	if ctx.ProbeRetEnter == -1 { return false }
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

// Result contains the formatted arguments and optional hex dump.
type Result struct {
	ArgParts   []string
	HexDumpStr string
	ReturnDesc string
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
