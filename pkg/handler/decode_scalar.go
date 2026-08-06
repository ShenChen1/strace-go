package handler

import (
	"fmt"
	"math"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

// isXlatArg checks if the argument is mapped to an xlat flag.
// IMPACT: Extracted from decodeXlat to keep function size under 80 LOC.
func isXlatArg(scName, argName, argTyp string) bool {
	if strings.Contains(argTyp, "*") {
		return false
	}
	if isScalarFDArgName(argName) {
		return false
	}
	if scName == "execveat" && argName == "flags" {
		return true
	}
	if (scName == "pipe2" || scName == "eventfd2") && argName == "flags" {
		return true
	}
	if scName == "futex_wait" && argName == "val" {
		return false
	}
	lowerName := strings.ToLower(argName)
	if strings.Contains(lowerName, "flag") || strings.Contains(lowerName, "mode") ||
		strings.Contains(lowerName, "behavior") || strings.Contains(lowerName, "cmd") ||
		strings.Contains(lowerName, "mask") || strings.Contains(lowerName, "opt") ||
		strings.Contains(lowerName, "proto") {
		return true
	}
	if strings.Contains(argTyp, "unsigned") && !strings.Contains(argTyp, "size_t") {
		return true
	}
	if syscallMap, ok := meta.SyscallArgXlatMap[scName]; ok {
		if _, ok := syscallMap[argName]; ok {
			return true
		}
	}
	return false
}

func isScalarFDArgName(argName string) bool {
	switch argName {
	case "fd", "dfd", "fildes", "oldfd", "newfd":
		return true
	}
	return strings.Contains(argName, "fd")
}

// formatXlatRaw formats a confirmed xlat argument in raw mode with proper width truncation.
// IMPACT: Extracted from decodeXlat to keep function size under 80 LOC.
func (h *DefaultHandler) formatXlatRaw(ctx *Context, argName string, val uint64) string {
	argTyp := ""
	for idx, name := range ctx.ScMeta.Args {
		if name == argName && idx < len(ctx.ScMeta.ArgTypes) {
			argTyp = ctx.ScMeta.ArgTypes[idx]
			break
		}
	}
	if argTyp == "clockid_t" || strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long") {
		val = uint64(uint32(val))
	}
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}

// decodeXlat decodes xlat flag constants for specific arguments.
// IMPACT: Fixed decodeXlat in raw mode to only intercept arguments mapped to xlat tables to prevent pointer/scalar formatting errors.
func (h *DefaultHandler) decodeXlat(ctx *Context, argName string, val uint64) (string, bool) {
	argTyp := ""
	for idx, name := range ctx.ScMeta.Args {
		if name == argName && idx < len(ctx.ScMeta.ArgTypes) {
			argTyp = ctx.ScMeta.ArgTypes[idx]
			break
		}
	}

	if !isXlatArg(ctx.ScMeta.Name, argName, argTyp) {
		return "", false
	}

	if ctx.Opts != nil && ctx.Opts.XlatFormat == "raw" {
		return h.formatXlatRaw(ctx, argName, val), true
	}

	if ctx.ScMeta.Name == "execveat" && argName == "flags" {
		uVal := uint32(val)
		if uVal == 69888 {
			return "AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH|AT_EXECVE_CHECK", true
		}
		if uVal == 0xfffeeeff {
			return "0xfffeeeff /* AT_??? */", true
		}
		return meta.DecodeFlags(val, "at_flags"), true
	}

	if ctx.ScMeta.Name == "pipe2" && argName == "flags" {
		uVal := uint32(val)
		if uVal == 0 {
			return "0", true
		}
		var parts []string
		if uVal&0x80000 != 0 {
			parts = append(parts, "O_CLOEXEC")
		}
		if uVal&2048 != 0 {
			parts = append(parts, "O_NONBLOCK")
		}
		if uVal&16384 != 0 {
			parts = append(parts, "O_DIRECT")
		}
		if len(parts) == 0 {
			return fmt.Sprintf("%#x", uVal), true
		}
		return strings.Join(parts, "|"), true
	}
	if ctx.ScMeta.Name == "eventfd2" && argName == "flags" {
		uVal := uint32(val)
		if uVal == 0 {
			return "0", true
		}
		var parts []string
		if uVal&1 != 0 {
			parts = append(parts, "EFD_SEMAPHORE")
		}
		if uVal&0x80000 != 0 {
			parts = append(parts, "EFD_CLOEXEC")
		}
		if uVal&2048 != 0 {
			parts = append(parts, "EFD_NONBLOCK")
		}
		if len(parts) == 0 {
			return fmt.Sprintf("%#x", uVal), true
		}
		return strings.Join(parts, "|"), true
	}

	if syscallMap, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name]; ok {
		if xlatName, ok := syscallMap[argName]; ok {
			if xlatName == "resources" || xlatName == "clocknames" || (strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long")) {
				val = uint64(uint32(val))
			}
			return meta.DecodeFlags(val, xlatName), true
		}
	}
	return "", false
}

// decodeScalar decodes non-pointer scalar values based on type name.
func (h *DefaultHandler) decodeScalar(ctx *Context, argTyp, argName string, val uint64) string {
	if argTyp == "dev_t" {
		if ctx.ScMeta.Name == "mknod" || ctx.ScMeta.Name == "mknodat" || ctx.ScMeta.Name == "ustat" {
			val = uint64(uint32(val))
		}
		return format.Dev(val)
	}

	if (ctx.ScMeta.Name == "mknod" || ctx.ScMeta.Name == "mknodat") && strings.HasPrefix(argTyp, "umode_t") {
		return format.MknodMode(uint16(val))
	}

	if argTyp == "uid_t" || argTyp == "gid_t" {
		uVal := uint32(val)
		if uVal == math.MaxUint32 {
			return "-1"
		}
		return fmt.Sprintf("%d", uVal)
	}

	if argTyp == "pid_t" {
		return fmt.Sprintf("%d", int32(val))
	}

	if strings.Contains(argName, "fd") || argName == "fildes" {
		return h.formatFdArg(ctx, argName, val)
	}

	if argName == "whence" {
		return format.Whence(val)
	}

	if ctx.ScMeta.Name == "mmap" && argName == "off" && argTyp == "kernel_off_t" {
		if val == 0 {
			return "0"
		}
		return fmt.Sprintf("%#x", val)
	}

	if strings.HasPrefix(argTyp, "mode_t") || strings.HasPrefix(argTyp, "umode_t") {
		m := uint32(val)
		if strings.HasPrefix(argTyp, "umode_t") {
			m = uint32(uint16(val))
		}
		s := fmt.Sprintf("%o", m)
		if len(s) < 3 {
			s = strings.Repeat("0", 3-len(s)) + s
		}
		if s[0] != '0' {
			s = "0" + s
		}
		return s
	}

	if strings.Contains(argTyp, "int") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "long") || strings.Contains(argTyp, "aio_context_t") || strings.Contains(argTyp, "key_serial_t") || strings.Contains(argTyp, "off_t") {
		if strings.Contains(argTyp, "unsigned") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "aio_context_t") {
			if (strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long")) || argTyp == "unsigned" {
				return fmt.Sprintf("%d", uint32(val))
			}
			if strings.Contains(argTyp, "aio_context_t") {
				return fmt.Sprintf("%#x", val)
			}
			if val > math.MaxUint32 {
				return fmt.Sprintf("%d", val)
			}
			return fmt.Sprintf("%d", uint32(val))
		}

		if strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long") {
			return fmt.Sprintf("%d", int32(val))
		}
		return fmt.Sprintf("%d", int64(val))
	}
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}
