package handler

// decodeStruct decodes structured pointer arguments.
func (h *DefaultHandler) decodeStruct(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if decoder := ctx.registry().StructDecoder(argTyp); decoder != nil {
		return decoder.Decode(ctx, i, argTyp, val)
	}
	return "", false
}
