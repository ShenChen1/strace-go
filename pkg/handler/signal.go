package handler

import (
	"strings"
	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &SignalHandler{}
	Register("rt_sigprocmask", h)
	Register("rt_sigaction", h)
	Register("rt_sigpending", h)
	Register("rt_sigsuspend", h)
}

type SignalHandler struct {
	DefaultHandler
}

func (h *SignalHandler) Handle(ctx *Context) Result {
	var res Result
	for i := 0; i < len(ctx.ScMeta.Args); i++ {
		argName, argTyp, val := ctx.ScMeta.Args[i], ctx.ScMeta.ArgTypes[i], ctx.Args[i]

		if argName == "how" {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, "sigprocmaskcmds"))
			continue
		}

		if (argName == "set" || argName == "oldset" || argName == "nset" || argName == "oset" || argName == "unblock" || argName == "mask") && strings.Contains(argTyp, "sigset_t") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}
			// fmt.Fprintf(os.Stderr, "DEBUG SIG: %s arg %s type %s\n", ctx.ScName, argName, argTyp)
			data := ctx.StrArgBuf[:8]
			if (argName == "oldset" || argName == "oset") && ctx.Ret >= 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, 8, true); err == nil { data = d }
			} else {
				if ctx.ProbeRetEnter < 0 {
					if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, 8, false); err == nil { data = d }
				}
			}
			res.ArgParts = append(res.ArgParts, format.Sigset(data))
			continue
		}

		if xlatName, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name][argName]; ok {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, xlatName))
		} else {
			// Fallback to default logic for single arg
			ctxCopy := *ctx
			ctxCopy.ScMeta.Args = []string{argName}
			ctxCopy.ScMeta.ArgTypes = []string{argTyp}
			ctxCopy.Args[0] = val
			defRes := h.DefaultHandler.Handle(&ctxCopy)
			res.ArgParts = append(res.ArgParts, defRes.ArgParts...)
		}
	}
	return res
}
