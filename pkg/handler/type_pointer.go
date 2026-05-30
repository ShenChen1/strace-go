package handler

import (
	"strings"
)

// PointerDecoder decodes specific pointer arguments, considering type, name, and result context.
type PointerDecoder interface {
	DecodePointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool)
}

var pointerDecoders = make(map[string]PointerDecoder)

// RegisterPointerDecoder registers a PointerDecoder for a specific type pattern.
func RegisterPointerDecoder(typPattern string, d PointerDecoder) {
	pointerDecoders[typPattern] = d
}

// PointerDecoderFunc is a convenience adapter.
type PointerDecoderFunc func(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool)

func (f PointerDecoderFunc) DecodePointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool) {
	return f(ctx, i, argTyp, argName, val, res)
}

// FindPointerDecoder attempts to find a decoder that matches the argument type.
func FindPointerDecoder(argTyp string) PointerDecoder {
	for pattern, decoder := range pointerDecoders {
		if strings.Contains(argTyp, pattern) {
			return decoder
		}
	}
	return nil
}
