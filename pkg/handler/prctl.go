package handler

import (
	"fmt"

	"strace-go/pkg/meta"
)

func init() {
	h := &PrctlHandler{}
	Register("prctl", h)
}

type PrctlHandler struct{}

func (h *PrctlHandler) Handle(ctx *Context) Result {
	res := Result{}
	option := int32(ctx.Args[0])
	res.ArgParts = append(res.ArgParts, meta.DecodeFlags(uint64(option), "prctl_options"))

	// Most prctl options use fewer than 5 arguments.
	// We'll decode based on option.
	
	switch option {
	case 15: // PR_SET_NAME
		res.ArgParts = append(res.ArgParts, ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[0:16], ctx.ArgProbeRet(1), "prctl", ctx.Opts.StringLimit))
	case 16: // PR_GET_NAME
		if ctx.Ret >= 0 {
			res.ArgParts = append(res.ArgParts, ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[1024:1040], ctx.ProbeRetExit, "prctl", ctx.Opts.StringLimit))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	case 1, 2, 3, 4, 11, 12, 13, 14, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 31, 32, 35, 36, 41, 42:
		// Options that take one integer/pointer argument
		if option == 1 { // PR_SET_PDEATHSIG
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(ctx.Args[1], "signalnames"))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	default:
		// Default to showing all non-zero arguments
		for i := 1; i < 5; i++ {
			if ctx.Args[i] != 0 || i == 1 {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[i]))
			}
		}
	}

	return res
}
