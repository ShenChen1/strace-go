package handler

import (
	"fmt"
)

// decodePointer formats pointer arguments, falling back to raw hex if needed.
func (h *DefaultHandler) decodePointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool) {
	if ctx != nil && ctx.Registry != nil {
		if decoder := ctx.Registry.PointerDecoder(argTyp); decoder != nil {
			if p, ok := decoder.DecodePointer(ctx, i, argTyp, argName, val, res); ok {
				return p, true
			}
		}
	}

	if val == 0 {
		return "NULL", true
	}
	return fmt.Sprintf("%#x", val), true
}
