package handler

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	Register("ioctl", &IoctlHandler{})
}

// IoctlHandler handles the complex formatting for the ioctl syscall.
type IoctlHandler struct {
	DefaultHandler
}

func (h *IoctlHandler) Handle(ctx *Context) Result {
	var res Result

	for i := 0; i < len(ctx.ScMeta.Args); i++ {
		val := ctx.Args[i]

		if i == 0 {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(val)))
			continue
		}

		if i == 1 {
			cmdName := ""
			switch val {
			case 0x5401: cmdName = "TCGETS"
			case 0x5402: cmdName = "TCSETS"
			case 0x5403: cmdName = "TCSETSW"
			case 0x5404: cmdName = "TCSETSF"
			case 0x5413: cmdName = "TIOCGWINSZ"
			case 0x5414: cmdName = "TIOCSWINSZ"
			case 0x541b: cmdName = "FIONREAD"
			case 0x5421: cmdName = "FIONBIO"
			case 0x5451: cmdName = "FIOASYNC"
			case 0x8912: cmdName = "SIOCGIFCONF"
			case 0x8913: cmdName = "SIOCGIFFLAGS"
			case 0x8914: cmdName = "SIOCSIFFLAGS"
			case 0x802c542a: cmdName = "TCGETS2"
			case 0x402c542b: cmdName = "TCSETS2"
			case 0x402c542c: cmdName = "TCSETSW2"
			case 0x402c542d: cmdName = "TCSETSF2"
			default: cmdName = meta.DecodeFlags(val, "term_cmds_overlapping")
			}
			res.ArgParts = append(res.ArgParts, cmdName)
			continue
		}

		if i == 2 {
			cmd := ctx.Args[1]
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
			} else {
				switch cmd {
				case 0x5401, 0x5402, 0x5403, 0x5404: // TCGETS, TCSETS, TCSETSW, TCSETSF
					res.ArgParts = append(res.ArgParts, format.Termios(ctx.StrArgBuf[512:512+60]))
				case 0x802c542a, 0x402c542b, 0x402c542c, 0x402c542d: // TCGETS2, TCSETS2, TCSETSW2, TCSETSF2
					res.ArgParts = append(res.ArgParts, format.Termios(ctx.StrArgBuf[512:512+44]))
				case 0x5413: // TIOCGWINSZ
					res.ArgParts = append(res.ArgParts, format.Winsize(ctx.StrArgBuf[512:512+8]))
				case 0x541b: // FIONREAD
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", binary.LittleEndian.Uint32(ctx.StrArgBuf[512:516])))
				default:
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				}
			}
			continue
		}
		
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
	}
	return res
}
