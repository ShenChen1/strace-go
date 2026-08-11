package handler

import "fmt"

func init() {
	Register("brk", &BrkHandler{})
	Register("mremap", &MremapHandler{})
}

type BrkHandler struct{}

func (h *BrkHandler) Handle(ctx *Context) Result {
	res := Result{}
	if ctx.Args[0] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	}
	return res
}

type MremapHandler struct{}

func (h *MremapHandler) Handle(ctx *Context) Result {
	flags := ctx.Args[3]
	argCount := len(ctx.ScMeta.ArgTypes)
	if (flags & 2) == 0 { // MREMAP_FIXED is 2
		argCount = 4
	}
	return handleDefaultWithCount(ctx, argCount)
}
