package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

func registerBuiltinProcessMadvise(r *Registry) {
	r.Register("process_madvise", &ProcessMadviseHandler{})
}

type ProcessMadviseHandler struct {
	DefaultHandler
}

func (h *ProcessMadviseHandler) Handle(ctx *Context) Result {
	return Result{ArgParts: []string{
		h.formatFdArg(ctx, "pidfd", ctx.Args[0]),
		formatProcessMadviseIovec(ctx, ctx.Args[1], ctx.Args[2]),
		h.decodeScalar(ctx, "size_t", "vlen", ctx.Args[2]),
		meta.DecodeFlags(uint64(uint32(ctx.Args[3])), "madvise_cmds"),
		formatProcessMadviseFlags(ctx.Args[4]),
	}}
}

func formatProcessMadviseIovec(ctx *Context, addr uint64, count uint64) string {
	if addr == 0 {
		return "NULL"
	}
	if count == 0 {
		return "[]"
	}

	readCount := int(count)
	if readCount > iovecDisplayLimit {
		readCount = iovecDisplayLimit
	}
	readSize := readCount * iovecSize
	data, ok := ctx.PayloadIovec(1, PayloadDirectionIn)
	if !ok || len(data) == 0 {
		return fmt.Sprintf("%#x", addr)
	}
	if len(data) > readSize {
		data = data[:readSize]
	}

	actualCount := len(data) / iovecSize
	parts := make([]string, 0, actualCount+1)
	for i := 0; i < actualCount; i++ {
		base := binary.LittleEndian.Uint64(data[i*iovecSize : i*iovecSize+8])
		length := binary.LittleEndian.Uint64(data[i*iovecSize+8 : i*iovecSize+iovecSize])
		parts = append(parts, fmt.Sprintf("{iov_base=%#x, iov_len=%d}", base, length))
	}
	if len(data) < readSize || int(count) > iovecDisplayLimit {
		parts = append(parts, fmt.Sprintf("... /* %#x */", addr+uint64(actualCount*iovecSize)))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatProcessMadviseFlags(val uint64) string {
	v := uint32(val)
	if v == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", v)
}
