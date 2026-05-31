package handler

import "strings"

// TypeDecoder decodes specific pointer or struct argument types.
type TypeDecoder interface {
	Decode(ctx *Context, i int, argTyp string, val uint64) (string, bool)
}

type structDecoderEntry struct {
	pattern string
	decoder TypeDecoder
}

// structDecoders contains decoders for various struct types.
var structDecoders []structDecoderEntry

// RegisterStructDecoder registers a TypeDecoder for a specific type pattern.
func RegisterStructDecoder(typPattern string, d TypeDecoder) {
	structDecoders = append(structDecoders, structDecoderEntry{typPattern, d})
}

// StructDecoderFunc is a convenience adapter to allow using ordinary functions as TypeDecoders.
type StructDecoderFunc func(ctx *Context, i int, argTyp string, val uint64) (string, bool)

// Decode calls f(ctx, i, argTyp, val).
func (f StructDecoderFunc) Decode(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	return f(ctx, i, argTyp, val)
}

// FindStructDecoder attempts to find a decoder that matches the argument type.
func FindStructDecoder(argTyp string) TypeDecoder {
	for _, entry := range structDecoders {
		if strings.Contains(argTyp, entry.pattern) {
			return entry.decoder
		}
	}
	return nil
}
