package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &FcntlHandler{}
	Register("fcntl", h)
	Register("fcntl64", h)
}

// FcntlHandler handles multi-type arg mapping for fcntl and fcntl64.
type FcntlHandler struct {
	DefaultHandler
}

const (
	fcntlFlockSize  = 32
	fcntlStructSize = 8
)

// Handle formats the arguments of the fcntl system call.
// IMPACT: Dispatches fcntl commands to structured flock, f_owner_ex, or flag decoders. Omits third arg for getter commands, translates return values.
func (h *FcntlHandler) Handle(ctx *Context) Result {
	res := Result{}
	fd := int32(ctx.Args[0])
	cmd := ctx.Args[1]
	arg := ctx.Args[2]

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", fd))

	// IMPACT: Mask higher 32 bits to prevent sign extension mismatch for fcntl cmd.
	cmdVal := uint32(cmd)
	cmdStr := h.decodeCmd(uint64(cmdVal))
	res.ArgParts = append(res.ArgParts, cmdStr)

	if !h.isNoArgCmd(cmdStr) {
		argStr := h.decodeArg(ctx, cmdStr, arg)
		res.ArgParts = append(res.ArgParts, argStr)
	}

	if ctx.Ret >= 0 {
		if cmdStr == "F_GETFD" && (ctx.Ret&1) != 0 {
			res.ReturnDesc = "flags FD_CLOEXEC"
		} else if cmdStr == "F_GETLEASE" {
			switch ctx.Ret {
			case 0:
				res.ReturnDesc = "F_RDLCK"
			case 1:
				res.ReturnDesc = "F_WRLCK"
			case 2:
				res.ReturnDesc = "F_UNLCK"
			}
		} else if cmdStr == "F_GETSIG" && ctx.Ret > 0 {
			res.ReturnDesc = meta.DecodeFlags(uint64(ctx.Ret), "signalnames")
		}
	}

	return res
}

func (h *FcntlHandler) decodeCmd(cmd uint64) string {
	// Normalize overlapping/libc-specific command values
	// IMPACT: Maps glibc/libc fcntl command numeric values directly to resolve differences between UAPI and glibc headers.
	switch cmd {
	case 36:
		return "F_OFD_GETLK"
	case 37:
		return "F_OFD_SETLK"
	case 38:
		return "F_OFD_SETLKW"
	case 15:
		return "F_SETOWN_EX"
	case 16:
		return "F_GETOWN_EX"
	case 1039:
		return "F_GETDELEG"
	case 1040:
		return "F_SETDELEG"
	}
	cmdStr := meta.DecodeFlags(cmd, "fcntlcmds")
	// Normalize overlapping xlat names to match strace upstream test assertions
	cmdStr = strings.ReplaceAll(cmdStr, "F_GETLK or F_GETLK64", "F_GETLK")
	cmdStr = strings.ReplaceAll(cmdStr, "F_SETLK or F_SETLK64", "F_SETLK")
	cmdStr = strings.ReplaceAll(cmdStr, "F_SETLKW or F_SETLKW64", "F_SETLKW")
	return cmdStr
}

func (h *FcntlHandler) decodeArg(ctx *Context, cmdStr string, arg uint64) string {
	if argStr, ok := h.decodeStructuredArg(ctx, cmdStr, arg); ok {
		return argStr
	}

	if cmdStr == "F_SETFL" {
		return meta.DecodeFlags(arg, "open_mode_flags")
	}

	if cmdStr == "F_SETFD" {
		// IMPACT: Decodes fd flags (like FD_CLOEXEC) for F_SETFD command.
		return meta.DecodeFlags(arg, "fdflags")
	}

	if cmdStr == "F_SETOWN" {
		return fmt.Sprintf("%d", int32(arg))
	}

	if cmdStr == "F_NOTIFY" {
		return meta.DecodeFlags(arg, "notifyflags")
	}

	if cmdStr == "F_SETLEASE" {
		return meta.DecodeFlags(arg, "lockfcmds")
	}

	if cmdStr == "F_SETSIG" {
		return meta.DecodeFlags(arg, "signalnames")
	}

	// Default formatting for other integer arguments
	return fmt.Sprintf("%d", int32(arg))
}

func (h *FcntlHandler) decodeStructuredArg(ctx *Context, cmdStr string, arg uint64) (string, bool) {
	if h.isLockCmd(cmdStr) {
		if arg == 0 {
			return "NULL", true
		}
		if strings.Contains(cmdStr, "GET") && ctx.Ret < 0 {
			return fmt.Sprintf("%#x", arg), true
		}
		return h.decodeFlock(ctx, cmdStr, arg), true
	}

	if cmdStr == "F_SETOWN_EX" || cmdStr == "F_GETOWN_EX" {
		if arg == 0 {
			return "NULL", true
		}
		return h.decodeFOwnerEx(ctx, arg, cmdStr == "F_GETOWN_EX"), true
	}

	if cmdStr == "F_SET_RW_HINT" || cmdStr == "F_SET_FILE_RW_HINT" {
		if arg == 0 {
			return "NULL", true
		}
		return h.decodeRwHint(ctx, arg, false), true
	}

	if cmdStr == "F_GET_RW_HINT" || cmdStr == "F_GET_FILE_RW_HINT" {
		if arg == 0 {
			return "NULL", true
		}
		if ctx.Ret < 0 {
			return fmt.Sprintf("%#x", arg), true
		}
		return h.decodeRwHint(ctx, arg, true), true
	}

	if cmdStr == "F_SETDELEG" {
		if arg == 0 {
			return "NULL", true
		}
		return h.decodeDelegation(ctx, arg, false), true
	}

	if cmdStr == "F_GETDELEG" {
		if arg == 0 {
			return "NULL", true
		}
		if ctx.Ret < 0 {
			return fmt.Sprintf("%#x", arg), true
		}
		return h.decodeDelegation(ctx, arg, true), true
	}

	return "", false
}

func (h *FcntlHandler) isLockCmd(cmdStr string) bool {
	return cmdStr == "F_GETLK" || cmdStr == "F_SETLK" || cmdStr == "F_SETLKW" ||
		cmdStr == "F_GETLK64" || cmdStr == "F_SETLK64" || cmdStr == "F_SETLKW64" ||
		cmdStr == "F_OFD_GETLK" || cmdStr == "F_OFD_SETLK" || cmdStr == "F_OFD_SETLKW"
}

func (h *FcntlHandler) decodeFlock(ctx *Context, cmdStr string, arg uint64) string {
	isGet := strings.Contains(cmdStr, "GETLK")
	data, ok := fcntlSnapshot(ctx, isGet, fcntlFlockSize)
	if !ok {
		return fmt.Sprintf("%#x", arg)
	}
	return format.Flock(data, isGet)
}

func (h *FcntlHandler) decodeFOwnerEx(ctx *Context, arg uint64, useExit bool) string {
	data, ok := fcntlSnapshot(ctx, useExit, fcntlStructSize)
	if !ok {
		return fmt.Sprintf("%#x", arg)
	}
	return format.FOwnerEx(data)
}

func (h *FcntlHandler) isNoArgCmd(cmdStr string) bool {
	return cmdStr == "F_GETFD" || cmdStr == "F_GETFL" || cmdStr == "F_GETOWN" ||
		cmdStr == "F_GETLEASE" || cmdStr == "F_GETSIG" || cmdStr == "F_GETPIPE_SZ"
}

func (h *FcntlHandler) decodeRwHint(ctx *Context, arg uint64, useExit bool) string {
	data, ok := fcntlSnapshot(ctx, useExit, fcntlStructSize)
	if !ok {
		return fmt.Sprintf("%#x", arg)
	}
	val := binary.LittleEndian.Uint64(data)
	hintStr := ""
	switch val {
	case 0:
		hintStr = "RWH_WRITE_LIFE_NOT_SET"
	case 1:
		hintStr = "RWH_WRITE_LIFE_NONE"
	case 2:
		hintStr = "RWH_WRITE_LIFE_SHORT"
	case 3:
		hintStr = "RWH_WRITE_LIFE_MEDIUM"
	case 4:
		hintStr = "RWH_WRITE_LIFE_LONG"
	case 5:
		hintStr = "RWH_WRITE_LIFE_EXTREME"
	default:
		hintStr = fmt.Sprintf("%#x /* RWH_WRITE_LIFE_??? */", val)
	}
	return "[" + hintStr + "]"
}

func (h *FcntlHandler) decodeDelegation(ctx *Context, arg uint64, useExit bool) string {
	data, ok := fcntlSnapshot(ctx, useExit, fcntlStructSize)
	if !ok {
		return fmt.Sprintf("%#x", arg)
	}
	return format.Delegation(data)
}

func fcntlSnapshot(ctx *Context, useExit bool, size int) ([]byte, bool) {
	if useExit {
		return ctx.ExitSnapshot(BpfExitArgOffset, size)
	}
	return ctx.EnterArgSnapshot(2, BpfEnterArgOffset, size)
}
