package handler

import (
	"fmt"
	"strings"
)

func init() {
	SetDefault(&DefaultHandler{})
}

// DefaultHandler handles all syscalls by default using metadata.
type DefaultHandler struct{}

// Handle formats the arguments of a system call based on type metadata.
func (h *DefaultHandler) Handle(ctx *Context) Result {
	return h.HandleWithCount(ctx, len(ctx.ScMeta.ArgTypes))
}

// HandleWithCount processes up to argCount arguments using default rules.
func (h *DefaultHandler) HandleWithCount(ctx *Context, argCount int) Result {
	res := Result{}

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

func handleDefaultWithCount(ctx *Context, argCount int) Result {
	if ctx == nil {
		return Result{}
	}
	defaultHandler := ctx.registry().Default()
	if defaultDecoder, ok := defaultHandler.(*DefaultHandler); ok {
		return defaultDecoder.HandleWithCount(ctx, argCount)
	}
	if defaultHandler == nil {
		return Result{}
	}
	return defaultHandler.Handle(ctx)
}
