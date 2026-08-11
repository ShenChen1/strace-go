package handler

import (
	"strings"
)

// PointerDecoder decodes specific pointer arguments, considering type, name, and result context.
type PointerDecoder interface {
	DecodePointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool)
}

type pointerDecoderEntry struct {
	pattern string
	decoder PointerDecoder
}

// RegisterPointerDecoder adds a pointer decoder to this registry.
func (r *Registry) RegisterPointerDecoder(typPattern string, d PointerDecoder) {
	if r == nil || typPattern == "" || d == nil {
		return
	}
	r.pointerDecoders = append(r.pointerDecoders, pointerDecoderEntry{typPattern, d})
}

// PointerDecoder finds the first decoder matching an argument type.
func (r *Registry) PointerDecoder(argTyp string) PointerDecoder {
	if r == nil {
		return nil
	}
	for _, entry := range r.pointerDecoders {
		if strings.Contains(argTyp, entry.pattern) {
			return entry.decoder
		}
	}
	return nil
}

// PointerDecoderFunc is a convenience adapter.
type PointerDecoderFunc func(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool)

func (f PointerDecoderFunc) DecodePointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool) {
	return f(ctx, i, argTyp, argName, val, res)
}
