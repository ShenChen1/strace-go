package handler

// decodeStruct decodes structured pointer arguments.
func (h *DefaultHandler) decodeStruct(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx != nil && ctx.Registry != nil {
		if decoder := ctx.Registry.StructDecoder(argTyp); decoder != nil {
			return decoder.Decode(ctx, i, argTyp, val)
		}
	}
	return "", false
}
