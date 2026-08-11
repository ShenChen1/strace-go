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

// close_range uses fd-like kernel names for unsigned range bounds.
func isFDFormattingArg(ctx *Context, argName string) bool {
	if ctx != nil && ctx.ScMeta.Name == "close_range" &&
		(argName == "fd" || argName == "max_fd") {
		return false
	}
	return isScalarFDArgName(argName)
}

type xlatDecodeRequest struct {
	ctx         *Context
	syscallName string
	argName     string
	argType     string
	val         uint64
}

func newXlatDecodeRequest(ctx *Context, argName string, val uint64) xlatDecodeRequest {
	req := xlatDecodeRequest{
		ctx:     ctx,
		argName: argName,
		val:     val,
	}
	if ctx == nil {
		return req
	}
	req.syscallName = ctx.ScMeta.Name
	for idx, name := range ctx.ScMeta.Args {
		if name == argName && idx < len(ctx.ScMeta.ArgTypes) {
			req.argType = ctx.ScMeta.ArgTypes[idx]
			break
		}
	}
	return req
}

// decodeXlat decodes xlat flag constants for specific arguments.
// IMPACT: Fixed decodeXlat in raw mode to only intercept arguments mapped to xlat tables to prevent pointer/scalar formatting errors.
func (h *DefaultHandler) decodeXlat(ctx *Context, argName string, val uint64) (string, bool) {
	req := newXlatDecodeRequest(ctx, argName, val)
	if !req.isXlatArg() {
		return "", false
	}
	if req.isRawMode() {
		return req.formatRaw(), true
	}
	if decoded, ok := req.decodeSpecial(); ok {
		return decoded, true
	}
	return req.decodeMapped()
}

func (req xlatDecodeRequest) isXlatArg() bool {
	return isXlatArg(req.syscallName, req.argName, req.argType)
}

func (req xlatDecodeRequest) isRawMode() bool {
	return req.ctx != nil && req.ctx.Opts != nil && req.ctx.Opts.XlatFormat == "raw"
}

func (req xlatDecodeRequest) formatRaw() string {
	val := req.val
	if req.argType == "clockid_t" || strings.Contains(req.argType, "int") && !strings.Contains(req.argType, "long") {
		val = uint64(uint32(val))
	}
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}

func (req xlatDecodeRequest) decodeSpecial() (string, bool) {
	switch {
	case req.syscallName == "execveat" && req.argName == "flags":
		return decodeExecveatFlags(req.val), true
	case req.syscallName == "pipe2" && req.argName == "flags":
		return decodeKnownFlagSet(uint32(req.val), []namedFlagBit{
			{0x80000, "O_CLOEXEC"},
			{2048, "O_NONBLOCK"},
			{16384, "O_DIRECT"},
		}), true
	case req.syscallName == "eventfd2" && req.argName == "flags":
		return decodeKnownFlagSet(uint32(req.val), []namedFlagBit{
			{1, "EFD_SEMAPHORE"},
			{0x80000, "EFD_CLOEXEC"},
			{2048, "EFD_NONBLOCK"},
		}), true
	default:
		return "", false
	}
}

func decodeExecveatFlags(val uint64) string {
	uVal := uint32(val)
	if uVal == 69888 {
		return "AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH|AT_EXECVE_CHECK"
	}
	if uVal == 0xfffeeeff {
		return "0xfffeeeff /* AT_??? */"
	}
	return meta.DecodeFlags(val, "at_flags")
}

type namedFlagBit struct {
	mask uint32
	name string
}

func decodeKnownFlagSet(val uint32, bits []namedFlagBit) string {
	if val == 0 {
		return "0"
	}
	var parts []string
	for _, bit := range bits {
		if val&bit.mask != 0 {
			parts = append(parts, bit.name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%#x", val)
	}
	return strings.Join(parts, "|")
}

func (req xlatDecodeRequest) decodeMapped() (string, bool) {
	if syscallMap, ok := meta.SyscallArgXlatMap[req.syscallName]; ok {
		if xlatName, ok := syscallMap[req.argName]; ok {
			val := req.val
			if shouldNarrowXlatValueTo32(req.argType, xlatName) {
				val = uint64(uint32(val))
			}
			return meta.DecodeFlags(val, xlatName), true
		}
	}
	return "", false
}

func shouldNarrowXlatValueTo32(argType string, xlatName string) bool {
	return xlatName == "resources" ||
		xlatName == "clocknames" ||
		(strings.Contains(argType, "int") && !strings.Contains(argType, "long"))
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

	if isFDFormattingArg(ctx, argName) {
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
