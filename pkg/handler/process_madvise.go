package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

func init() {
	Register("process_madvise", &ProcessMadviseHandler{})
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

	const limit = 16
	readCount := int(count)
	if readCount > limit {
		readCount = limit
	}
	data, _ := ctx.MemReader.ReadRobust(ctx.Tid, addr, readCount*16, true)
	if len(data) == 0 {
		return fmt.Sprintf("%#x", addr)
	}

	actualCount := len(data) / 16
	parts := make([]string, 0, actualCount+1)
	for i := 0; i < actualCount; i++ {
		base := binary.LittleEndian.Uint64(data[i*16 : i*16+8])
		length := binary.LittleEndian.Uint64(data[i*16+8 : i*16+16])
		parts = append(parts, fmt.Sprintf("{iov_base=%#x, iov_len=%d}", base, length))
	}
	if len(data) < readCount*16 || int(count) > limit {
		parts = append(parts, fmt.Sprintf("... /* %#x */", addr+uint64(actualCount*16)))
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
