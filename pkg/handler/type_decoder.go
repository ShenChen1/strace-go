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

// RegisterStructDecoder adds a struct decoder to this registry.
func (r *Registry) RegisterStructDecoder(typPattern string, d TypeDecoder) {
	if r == nil || typPattern == "" || d == nil {
		return
	}
	r.structDecoders = append(r.structDecoders, structDecoderEntry{typPattern, d})
}

// StructDecoder finds the first decoder matching an argument type.
func (r *Registry) StructDecoder(argTyp string) TypeDecoder {
	if r == nil {
		return nil
	}
	for _, entry := range r.structDecoders {
		if strings.Contains(argTyp, entry.pattern) {
			return entry.decoder
		}
	}
	return nil
}

// RegisterStructDecoder registers a TypeDecoder for a specific type pattern.
func RegisterStructDecoder(typPattern string, d TypeDecoder) {
	builtinRegistry.RegisterStructDecoder(typPattern, d)
}

// StructDecoderFunc is a convenience adapter to allow using ordinary functions as TypeDecoders.
type StructDecoderFunc func(ctx *Context, i int, argTyp string, val uint64) (string, bool)

// Decode calls f(ctx, i, argTyp, val).
func (f StructDecoderFunc) Decode(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	return f(ctx, i, argTyp, val)
}

// FindStructDecoder attempts to find a decoder that matches the argument type.
func FindStructDecoder(argTyp string) TypeDecoder {
	return builtinRegistry.StructDecoder(argTyp)
}
