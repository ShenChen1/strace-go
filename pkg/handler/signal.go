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
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}
			data := ctx.StrArgBuf[:8]
			if (argName == "oldset" || argName == "oset") && ctx.Ret >= 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 8, true); err == nil && len(d) == 8 { data = d }
			} else {
				if ctx.ProbeRetEnter < 0 {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 8, false); err == nil && len(d) == 8 { data = d }
				}
			}
			res.ArgParts = append(res.ArgParts, format.Sigset(data))
			continue
		}

		if (argName == "act" || argName == "oact") && strings.Contains(argTyp, "sigaction") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}
			data := ctx.StrArgBuf[0:32]
			if argName == "oact" { data = ctx.StrArgBuf[1024:1056] }
			
			readSuccess := ctx.ProbeRetEnter >= 0
			if argName == "oact" { readSuccess = ctx.ProbeRetExit >= 0 }
			
			if !readSuccess {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 32, argName == "oact"); err == nil && len(d) == 32 {
					data = d
					readSuccess = true
				}
			}
			
			if readSuccess {
				res.ArgParts = append(res.ArgParts, formatSigaction(data))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
			}
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

func formatSigaction(data []byte) string {
	if len(data) < 32 { return "{...}" }
	handler := binary.LittleEndian.Uint64(data[0:8])
	flags := binary.LittleEndian.Uint64(data[8:16])
	restorer := binary.LittleEndian.Uint64(data[16:24])
	
	hStr := ""
	if handler == 0 { hStr = "SIG_DFL" } else if handler == 1 { hStr = "SIG_IGN" } else { hStr = fmt.Sprintf("%#x", handler) }
	
	res := fmt.Sprintf("{sa_handler=%s, sa_mask=%s, sa_flags=%s", hStr, format.Sigset(data[24:32]), meta.DecodeFlags(flags, "sigact_flags"))
	if flags & 0x04000000 != 0 { // SA_RESTORER
		res += fmt.Sprintf(", sa_restorer=%#x", restorer)
	}
	res += "}"
	return res
}
