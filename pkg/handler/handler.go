// Package handler provides a registry-based architecture for decoding syscall arguments.
package handler

import (
	"fmt"
	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
	"strace-go/pkg/procmem"
)

const (
	// BpfEnterArgOffset is the starting offset for args collected on syscall enter.
	BpfEnterArgOffset = 0
	// BpfMiscArgOffset is the starting offset for misc/secondary args in BPF buffers.
	BpfMiscArgOffset = 512
	// BpfExitArgOffset is the starting offset for args collected on syscall exit.
	BpfExitArgOffset = 1024
	// AtFdcwd is the magic file descriptor value for AT_FDCWD.
	AtFdcwd = -100
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
	MemReader procmem.MemoryReader
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

// FetchStructData safely retrieves memory for a struct pointer.
// It prioritizes BPF-captured buffer if successful, otherwise falls back to reading from process memory.
// It may return fewer bytes than requested if a page boundary fault occurs.
func (ctx *Context) FetchStructData(ptr uint64, size int, isExit bool, bpfBuf []byte) ([]byte, bool) {
	var data []byte
	readSuccess := false

	if isExit {
		if ctx.ProbeRetExit >= 0 {
			if len(bpfBuf) >= size {
				data = bpfBuf[:size]
			} else {
				data = bpfBuf
			}
			readSuccess = true
		}
	} else {
		if ctx.ProbeRetEnter >= 0 {
			if len(bpfBuf) >= size {
				data = bpfBuf[:size]
			} else {
				data = bpfBuf
			}
			readSuccess = true
		}
	}

	if !readSuccess {
		if d, err := ctx.MemReader.ReadRobust(ctx.Tid, ptr, size, false); err == nil && len(d) > 0 {
			data = d
			readSuccess = true
		}
	}

	return data, readSuccess
}

// FetchStructDataExact is like FetchStructData but strictly requires the full requested size.
func (ctx *Context) FetchStructDataExact(ptr uint64, size int, isExit bool, bpfBuf []byte) ([]byte, bool) {
	data, ok := ctx.FetchStructData(ptr, size, isExit, bpfBuf)
	if ok && len(data) == size {
		return data, true
	}
	return nil, false
}

// DecodeStructWithFallback handles NULL checks and fallback hex formatting for struct pointers.
func (ctx *Context) DecodeStructWithFallback(val uint64, size int, isExit bool, bpfBuf []byte, decodeFn func([]byte) string) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	data, ok := ctx.FetchStructDataExact(val, size, isExit, bpfBuf)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return decodeFn(data), true
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

// GetDefault returns the default handler.
func GetDefault() Handler {
	return defaultHandler
}
