package handler

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/meta"
)

func init() {
	h := &PrctlHandler{}
	Register("prctl", h)
}

type PrctlHandler struct{}

const prctlNameSize = 16

func (h *PrctlHandler) Handle(ctx *Context) Result {
	res := Result{}
	option := int32(ctx.Args[0])
	res.ArgParts = append(res.ArgParts, meta.DecodeFlags(uint64(option), "prctl_options"))

	switch option {
	case 15: // PR_SET_NAME
		res.ArgParts = append(res.ArgParts, decodePrctlName(ctx, false))
		return res
	case 16: // PR_GET_NAME
		if ctx.Ret >= 0 {
			res.ArgParts = append(res.ArgParts, decodePrctlName(ctx, true))
		} else {
			res.ArgParts = append(res.ArgParts, formatPtrFallback(ctx.Args[1]))
		}
		return res
	case 1: // PR_GET_PDEATHSIG
		if ctx.Ret >= 0 && ctx.Args[1] != 0 {
			data, ok := prctlUint32OutPayload(ctx)
			if ok {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%s]", meta.DecodeFlags(uint64(binary.LittleEndian.Uint32(data)), "signalnames")))
			} else {
				res.ArgParts = append(res.ArgParts, formatPtrFallback(ctx.Args[1]))
			}
		} else {
			res.ArgParts = append(res.ArgParts, formatPtrFallback(ctx.Args[1]))
		}
		return res
	case 2: // PR_SET_PDEATHSIG
		res.ArgParts = append(res.ArgParts, meta.DecodeFlags(ctx.Args[1], "signalnames"))
		return res
	case 9, 11, 19, 37, 5, 25: // PR_GET_FPEMU, PR_GET_FPEXC, PR_GET_ENDIAN, PR_GET_CHILD_SUBREAPER, PR_GET_UNALIGN, PR_GET_TSC
		if ctx.Ret >= 0 && ctx.Args[1] != 0 {
			data, ok := prctlUint32OutPayload(ctx)
			if ok {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", int32(binary.LittleEndian.Uint32(data))))
			} else {
				res.ArgParts = append(res.ArgParts, formatPtrFallback(ctx.Args[1]))
			}
		} else {
			res.ArgParts = append(res.ArgParts, formatPtrFallback(ctx.Args[1]))
		}
		return res
	case 3, 7, 13, 21, 30, 31, 32, 34, 39, 40, 42, 46, 51, 52, 56, 58, 61, 64, 66, 68, 70, 80:
		// 0 args
		return res
	case 4, 6, 8, 10, 12, 14, 20, 22, 23, 24, 26, 27, 28, 35, 36, 38, 41, 45, 50, 53, 55, 57, 59, 63, 65, 67, 69, 75, 81:
		// 1 arg
		res.ArgParts = append(res.ArgParts, formatPtrFallback(ctx.Args[1]))
		return res
	case 33: // PR_MCE_KILL
		res.ArgParts = append(res.ArgParts, formatPtrFallback(ctx.Args[1]))
		if ctx.Args[1] == 1 { // PR_MCE_KILL_SET
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
		return res
	}

	// Default to showing all non-zero arguments
	for i := 1; i < 5; i++ {
		if ctx.Args[i] != 0 {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[i]))
		} else if i == 1 {
			// upstream strace usually shows arg1 if we don't know the arity, let's keep it if nothing else
			res.ArgParts = append(res.ArgParts, "0")
		}
	}
	return res
}

func decodePrctlName(ctx *Context, isExit bool) string {
	direction := PayloadDirectionIn
	if isExit {
		direction = PayloadDirectionOut
	}
	limit := -1
	if ctx.Opts != nil {
		limit = ctx.Opts.StringLimit
	}
	if text, ok := ctx.PayloadString(1, direction, ctx.Args[1], limit); ok {
		return text
	}
	return formatPtrFallback(ctx.Args[1])
}

func prctlUint32OutPayload(ctx *Context) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(1, PayloadDirectionOut); ok && len(data) >= 4 {
		return data[:4], true
	}
	return nil, false
}

func formatPtrFallback(val uint64) string {
	if val == 0 {
		return "NULL"
	}
	return fmt.Sprintf("%#x", val)
}
