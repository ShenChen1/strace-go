package handler

import (
	"encoding/binary"
	"fmt"
)

func init() {
	Register("sendfile", &SendfileHandler{})
}

type SendfileHandler struct {
	DefaultHandler
}

func (h *SendfileHandler) Handle(ctx *Context) Result {
	return Result{ArgParts: []string{
		h.formatFdArg(ctx, "out_fd", ctx.Args[0]),
		h.formatFdArg(ctx, "in_fd", ctx.Args[1]),
		formatSendfileOffset(ctx),
		h.decodeScalar(ctx, "size_t", "count", ctx.Args[3]),
	}}
}

func formatSendfileOffset(ctx *Context) string {
	ptr := ctx.Args[2]
	if ptr == 0 {
		return "NULL"
	}

	enter, ok := fetchSendfileOffset(ctx, PayloadDirectionIn)
	if !ok {
		return fmt.Sprintf("%#x", ptr)
	}

	if ctx.Ret >= 0 {
		if exit, ok := fetchSendfileOffset(ctx, PayloadDirectionOut); ok && exit != enter {
			return fmt.Sprintf("[%d => %d]", enter, exit)
		}
	}
	return fmt.Sprintf("[%d]", enter)
}

func fetchSendfileOffset(ctx *Context, direction PayloadDirection) (uint64, bool) {
	data, ok := sendfileOffsetPayload(ctx, direction)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint64(data), true
}

func sendfileOffsetPayload(ctx *Context, direction PayloadDirection) ([]byte, bool) {
	data, ok := ctx.PayloadStruct(2, direction)
	if !ok || len(data) < 8 {
		return nil, false
	}
	return data[:8], true
}
