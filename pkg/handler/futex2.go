package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

const (
	futexWaitvSize          = 24
	futexWaitvMax           = 128
	futexWaitvTimeoutOffset = futexWaitvSize * futexWaitvMax
)

func init() {
	RegisterStructDecoder("struct futex_waitv *", StructDecoderFunc(decodeFutexWaitvArray))
}

func decodeFutexWaitvArray(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	count, ok := futexWaitvCount(ctx)
	if !ok {
		return "", false
	}
	return formatFutexWaitvArray(ctx, i, val, count), true
}

func futexWaitvCount(ctx *Context) (uint32, bool) {
	switch ctx.ScMeta.Name {
	case "futex_waitv":
		return uint32(ctx.Args[1]), true
	case "futex_requeue":
		return 2, true
	default:
		return 0, false
	}
}

func formatFutexWaitvArray(ctx *Context, argIndex int, ptr uint64, count uint32) string {
	if count == 0 {
		return "[]"
	}

	limit := count
	if limit > futexWaitvMax {
		limit = futexWaitvMax
	}
	size := int(limit) * futexWaitvSize
	data, ok := ctx.fetchFutexWaitvData(argIndex, size)
	if !ok || len(data) < futexWaitvSize {
		return fmt.Sprintf("%#x", ptr)
	}

	parts := make([]string, 0, limit+1)
	idx := uint32(0)
	for ; idx < limit; idx++ {
		off := int(idx) * futexWaitvSize
		if off+futexWaitvSize > len(data) {
			parts = append(parts, fmt.Sprintf("... /* %#x */", ptr+uint64(off)))
			break
		}
		parts = append(parts, formatFutexWaitv(data[off:off+futexWaitvSize]))
	}
	if idx == limit && count > futexWaitvMax {
		parts = append(parts, "...")
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func (ctx *Context) fetchFutexWaitvData(argIndex int, size int) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func formatFutexWaitv(data []byte) string {
	val := binary.LittleEndian.Uint64(data[0:8])
	uaddr := binary.LittleEndian.Uint64(data[8:16])
	flags := binary.LittleEndian.Uint32(data[16:20])
	reserved := binary.LittleEndian.Uint32(data[20:24])

	uaddrText := "NULL"
	if uaddr != 0 {
		uaddrText = fmt.Sprintf("%#x", uaddr)
	}

	parts := []string{
		"val=" + formatFutexHex(val),
		"uaddr=" + uaddrText,
		"flags=" + meta.DecodeFlags(uint64(flags), "futex2_flags"),
	}
	if reserved != 0 {
		parts = append(parts, fmt.Sprintf("__reserved=%#x", reserved))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func formatFutexHex(val uint64) string {
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}
