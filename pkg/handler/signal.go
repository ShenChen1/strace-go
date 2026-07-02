package handler

import (
	"encoding/binary"
	"fmt"
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

const (
	signalSigsetSize    = 8
	signalSigactionSize = 32
)

// IMPACT: Handle formats signal-related system calls.
// Added specific parameter normalization mapping for rt_sigsuspend to utilize existing Sigset formatting logic.
func (h *SignalHandler) Handle(ctx *Context) Result {
	res := Result{}
	for i := 0; i < len(ctx.ScMeta.Args); i++ {
		argName, argTyp, val := ctx.ScMeta.Args[i], ctx.ScMeta.ArgTypes[i], ctx.Args[i]
		if ctx.ScMeta.Name == "rt_sigsuspend" {
			if i == 0 {
				argName = "set"
				argTyp = "sigset_t *"
			} else if i == 1 {
				argName = "sigsetsize"
				argTyp = "size_t"
			}
		}

		if argName == "sig" {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, "signalnames"))
			continue
		}

		if argName == "how" {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, "sigprocmaskcmds"))
			continue
		}

		if (argName == "set" || argName == "oldset" || argName == "nset" || argName == "oset" || argName == "unblock" || argName == "mask") && strings.Contains(argTyp, "sigset_t") {
			res.ArgParts = append(res.ArgParts, h.formatSigsetArg(ctx, i, argName, val))
			continue
		}

		if (argName == "act" || argName == "oact") && strings.Contains(argTyp, "sigaction") {
			res.ArgParts = append(res.ArgParts, h.formatSigactionArg(ctx, i, argName, val))
			continue
		}

		if argName == "sigsetsize" {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", val))
			continue
		}

		if xlatName, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name][argName]; ok {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, xlatName))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
		}
	}
	return res
}

func (h *SignalHandler) formatSigsetArg(ctx *Context, argIndex int, argName string, val uint64) string {
	if val == 0 {
		return "NULL"
	}
	if ctx.ScMeta.Name == "rt_sigsuspend" && ctx.Args[1] != 8 {
		return fmt.Sprintf("%#x", val)
	}
	if (argName == "oldset" || argName == "oset") && ctx.Ret >= 0 {
		data, ok := signalStructSnapshot(ctx, argIndex, PayloadDirectionOut, BpfExitArgOffset, signalSigsetSize)
		if ok {
			return format.Sigset(data)
		}
		return fmt.Sprintf("%#x", val)
	} else {
		data, ok := signalStructSnapshot(ctx, argIndex, PayloadDirectionIn, BpfEnterArgOffset, signalSigsetSize)
		if ok {
			return format.Sigset(data)
		}
	}
	return "[]"
}

func (h *SignalHandler) formatSigactionArg(ctx *Context, argIndex int, argName string, val uint64) string {
	if val == 0 {
		return "NULL"
	}
	if argName == "oact" {
		data, ok := signalStructSnapshot(ctx, argIndex, PayloadDirectionOut, BpfExitArgOffset, signalSigactionSize)
		if ok {
			return formatSigaction(data)
		}
		return fmt.Sprintf("%#x", val)
	}

	if data, ok := signalStructSnapshot(ctx, argIndex, PayloadDirectionIn, BpfEnterArgOffset, signalSigactionSize); ok {
		return formatSigaction(data)
	}
	return fmt.Sprintf("%#x", val)
}

func signalStructSnapshot(
	ctx *Context,
	argIndex int,
	direction PayloadDirection,
	offset int,
	size int,
) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, direction); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func formatSigaction(data []byte) string {
	if len(data) < 32 {
		return "{...}"
	}
	handler := binary.LittleEndian.Uint64(data[0:8])
	flags := binary.LittleEndian.Uint64(data[8:16])
	restorer := binary.LittleEndian.Uint64(data[16:24])

	hStr := ""
	if handler == 0 {
		hStr = "SIG_DFL"
	} else if handler == 1 {
		hStr = "SIG_IGN"
	} else {
		hStr = fmt.Sprintf("%#x", handler)
	}

	res := fmt.Sprintf("{sa_handler=%s, sa_mask=%s, sa_flags=%s", hStr, format.Sigset(data[24:32]), meta.DecodeFlags(flags, "sigact_flags"))
	if flags&0x04000000 != 0 { // SA_RESTORER
		res += fmt.Sprintf(", sa_restorer=%#x", restorer)
	}
	res += "}"
	return res
}
