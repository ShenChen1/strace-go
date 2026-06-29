package handler

import (
	"encoding/binary"
	"fmt"
)

const (
	copyFileRangeOffInOffset  = BpfMiscArgOffset
	copyFileRangeOffOutOffset = BpfMiscArgOffset + 8
)

func init() {
	Register("copy_file_range", &CopyFileRangeHandler{})
}

type CopyFileRangeHandler struct {
	DefaultHandler
}

func (h *CopyFileRangeHandler) Handle(ctx *Context) Result {
	return Result{ArgParts: []string{
		h.formatFdArg(ctx, "fd_in", ctx.Args[0]),
		formatLoffPointer(ctx, 1, copyFileRangeOffInOffset, ctx.Args[1]),
		h.formatFdArg(ctx, "fd_out", ctx.Args[2]),
		formatLoffPointer(ctx, 3, copyFileRangeOffOutOffset, ctx.Args[3]),
		h.decodeScalar(ctx, "size_t", "len", ctx.Args[4]),
		h.decodeScalar(ctx, "unsigned int", "flags", ctx.Args[5]),
	}}
}

func formatLoffPointer(ctx *Context, argIndex, offset int, ptr uint64) string {
	if ptr == 0 {
		return "NULL"
	}

	data, ok := ctx.EnterArgSnapshot(argIndex, offset, 8)
	if !ok {
		return fmt.Sprintf("%#x", ptr)
	}
	return fmt.Sprintf("[%d]", int64(binary.LittleEndian.Uint64(data)))
}
