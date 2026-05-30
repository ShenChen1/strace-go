package handler

import "strings"

// TypeDecoder decodes specific pointer or struct argument types.
type TypeDecoder interface {
	Decode(ctx *Context, i int, argTyp string, val uint64) (string, bool)
}

// structDecoders contains decoders for various struct types.
// The key is a substring expected to be in argTyp (e.g., "struct timespec *").
var structDecoders = make(map[string]TypeDecoder)

// RegisterStructDecoder registers a TypeDecoder for a specific type pattern.
func RegisterStructDecoder(typPattern string, d TypeDecoder) {
	structDecoders[typPattern] = d
}

// StructDecoderFunc is a convenience adapter to allow using ordinary functions as TypeDecoders.
type StructDecoderFunc func(ctx *Context, i int, argTyp string, val uint64) (string, bool)

// Decode calls f(ctx, i, argTyp, val).
func (f StructDecoderFunc) Decode(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	return f(ctx, i, argTyp, val)
}

// FindStructDecoder attempts to find a decoder that matches the argument type.
func FindStructDecoder(argTyp string) TypeDecoder {
	for pattern, decoder := range structDecoders {
		if strings.Contains(argTyp, pattern) {
			return decoder
		}
	}
	return nil
}
