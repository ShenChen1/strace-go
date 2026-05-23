package handler

import (
	"fmt"
	"strings"
	"sync"
)

var (
	execveatCountLock sync.Mutex
	execveatCallCount int
)

func init() {
	SetDefault(&DefaultHandler{})
}

// DefaultHandler handles all syscalls by default using metadata.
type DefaultHandler struct{}

func (h *DefaultHandler) getArgCount(ctx *Context) int {
	argCount := len(ctx.ScMeta.ArgTypes)
	switch ctx.ScMeta.Name {
	case "open", "openat":
		flags := uint32(ctx.Args[1])
		if ctx.ScMeta.Name == "openat" {
			flags = uint32(ctx.Args[2])
		}
		hasMode := (flags&0100 != 0) || (flags&020000000 != 0)
		if !hasMode {
			if ctx.ScMeta.Name == "open" {
				return 2
			}
			return 3
		}
	case "mknod", "mknodat":
		modeIdx := 1
		if ctx.ScMeta.Name == "mknodat" {
			modeIdx = 2
		}
		mode := uint16(ctx.Args[modeIdx])
		typeVal := mode & 0170000
		if typeVal != 0020000 && typeVal != 0060000 {
			if ctx.ScMeta.Name == "mknod" {
				return 2
			}
			return 3
		}
	case "mremap":
		flags := ctx.Args[3]
		if (flags & 2) == 0 { // MREMAP_FIXED is 2
			return 4
		}
	}
	return argCount
}

// Handle formats the arguments of a system call based on type metadata.
func (h *DefaultHandler) Handle(ctx *Context) Result {
	res := Result{}

	if ctx.ScMeta.Name == "execveat" {
		execveatCountLock.Lock()
		execveatCallCount++
		execveatCountLock.Unlock()
	}

	if ctx.ScMeta.Name == "brk" {
		if ctx.Args[0] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
		}
		return res
	}

	argCount := h.getArgCount(ctx)

	for i := 0; i < argCount; i++ {
		argTyp := ctx.ScMeta.ArgTypes[i]
		argName := ctx.ScMeta.Args[i]
		val := ctx.Args[i]

		// Handle XLATs
		if part, ok := h.decodeXlat(ctx, argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}

		if strings.Contains(argTyp, "*") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}

			// Priority decoding for well-known structs
			if part, ok := h.decodeStruct(ctx, i, argTyp, val); ok {
				res.ArgParts = append(res.ArgParts, part)
				continue
			}

			// Fallback to strings or hex pointers
			if part, ok := h.decodePointer(ctx, i, argTyp, argName, val, &res); ok {
				res.ArgParts = append(res.ArgParts, part)
				continue
			}

			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
			continue
		}

		res.ArgParts = append(res.ArgParts, h.decodeScalar(ctx, argTyp, argName, val))
	}
	return res
}
