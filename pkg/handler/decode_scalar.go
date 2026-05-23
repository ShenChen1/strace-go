package handler

import (
	"fmt"
	"os"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

// decodeXlat decodes xlat flag constants for specific arguments.
func (h *DefaultHandler) decodeXlat(ctx *Context, argName string, val uint64) (string, bool) {
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

	if syscallMap, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name]; ok {
		if xlatName, ok := syscallMap[argName]; ok {
			if xlatName == "resources" {
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
		return format.Dev(val)
	}

	if (ctx.ScMeta.Name == "mknod" || ctx.ScMeta.Name == "mknodat") && strings.HasPrefix(argTyp, "umode_t") {
		return format.MknodMode(uint16(val))
	}

	if argTyp == "uid_t" || argTyp == "gid_t" {
		uVal := uint32(val)
		if uVal == 0xffffffff {
			return "-1"
		}
		return fmt.Sprintf("%d", uVal)
	}

	if argTyp == "pid_t" {
		return fmt.Sprintf("%d", int32(val))
	}

	if strings.Contains(argName, "fd") || argName == "fildes" {
		if int32(val) == -100 {
			s := "AT_FDCWD"
			if ctx.Opts.ShowPaths {
				if l, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ctx.Pid)); err == nil {
					s += "<" + l + ">"
				}
			}
			return s
		}
		return fmt.Sprintf("%d", int32(val))
	}

	if argName == "whence" {
		return format.Whence(val)
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

	if strings.Contains(argTyp, "int") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "long") || strings.Contains(argTyp, "aio_context_t") || strings.Contains(argTyp, "key_serial_t") {
		if strings.Contains(argTyp, "unsigned") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "aio_context_t") {
			if (strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long")) || argTyp == "unsigned" {
				return fmt.Sprintf("%d", uint32(val))
			}
			if strings.Contains(argTyp, "aio_context_t") {
				return fmt.Sprintf("%#x", val)
			}
			if val > 0xffffffff {
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
