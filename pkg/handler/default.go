package handler

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	SetDefault(&DefaultHandler{})
}

// DefaultHandler handles all syscalls by default using metadata.
type DefaultHandler struct{}

func (h *DefaultHandler) getArgCount(ctx *Context) int {
	argCount := len(ctx.ScMeta.ArgTypes)
	switch ctx.ScMeta.Name {
	case "open", "openat":
		flags := uint32(ctx.Args[1])
		if ctx.ScMeta.Name == "openat" {
			flags = uint32(ctx.Args[2])
		}
		hasMode := (flags&0100 != 0) || (flags&020000000 != 0)
		if !hasMode {
			if ctx.ScMeta.Name == "open" {
				return 2
			}
			return 3
		}
	case "mknod", "mknodat":
		modeIdx := 1
		if ctx.ScMeta.Name == "mknodat" {
			modeIdx = 2
		}
		mode := uint16(ctx.Args[modeIdx])
		typeVal := mode & 0170000
		if typeVal != 0020000 && typeVal != 0060000 {
			if ctx.ScMeta.Name == "mknod" {
				return 2
			}
			return 3
		}
	case "mremap":
		flags := ctx.Args[3]
		if (flags & 2) == 0 { // MREMAP_FIXED is 2
			return 4
		}
	}
	return argCount
}

// Handle formats the arguments of a system call based on type metadata.
// Impact: Core entry point for decoding syscall arguments. Changes here
// affect formatting of pointers, strings, structs, and xlat constants.
func (h *DefaultHandler) Handle(ctx *Context) Result {
	res := Result{}

	if ctx.ScMeta.Name == "brk" {
		if ctx.Args[0] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
		}
		return res
	}

	argCount := h.getArgCount(ctx)

	for i := 0; i < argCount; i++ {
		argTyp := ctx.ScMeta.ArgTypes[i]
		argName := ctx.ScMeta.Args[i]
		val := ctx.Args[i]

		// Handle XLATs
		if part, ok := h.decodeXlat(ctx, argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}

		if strings.Contains(argTyp, "*") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}

			// Priority decoding for well-known structs
			if part, ok := h.decodeStruct(ctx, argTyp, val); ok {
				res.ArgParts = append(res.ArgParts, part)
				continue
			}

			// Fallback to strings or hex pointers
			if part, ok := h.decodePointer(ctx, i, argTyp, argName, val, &res); ok {
				res.ArgParts = append(res.ArgParts, part)
				continue
			}

			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
			continue
		}

		res.ArgParts = append(res.ArgParts, h.decodeScalar(ctx, argTyp, argName, val))
	}
	return res
}

func (h *DefaultHandler) decodeXlat(ctx *Context, argName string, val uint64) (string, bool) {
	if syscallMap, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name]; ok {
		if xlatName, ok := syscallMap[argName]; ok {
			return meta.DecodeFlags(val, xlatName), true
		}
	}
	return "", false
}

// Impact: Decodes structured pointer arguments such as timespec arrays or stats.
// Adding support for utimensat structure decoding.
func (h *DefaultHandler) decodeStruct(ctx *Context, argTyp string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "utimensat" && strings.Contains(argTyp, "struct timespec *") {
		data := ctx.StrArgBuf[512 : 512+32]
		readSuccess := ctx.IsArgReadSuccess(1)
		var err error
		if !readSuccess || ctx.ProbeRetEnter < 0 {
			data, err = ctx.MemReader.ReadRobust(ctx.Pid, val, 32, false)
			readSuccess = (err == nil && len(data) == 32)
		}
		if !readSuccess {
			return fmt.Sprintf("%#x", val), true
		}
		return format.Utimes(data), true
	}

	if strings.Contains(argTyp, "struct timespec *") || strings.Contains(argTyp, "struct __kernel_timespec *") {
		off := 0
		data := ctx.StrArgBuf[off : off+16]
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 || ctx.ScMeta.Name == "nanosleep" || ctx.ScMeta.Name == "clock_nanosleep" {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false); err == nil && len(d) == 16 {
				data = d
			}
		}
		return format.Timespec(data), true
	}

	if strings.Contains(argTyp, "struct timeval *") {
		data := ctx.StrArgBuf[1024 : 1024+16]
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false); err == nil && len(d) == 16 {
				data = d
			}
		}
		return format.Timeval(data), true
	}

	if strings.Contains(argTyp, "struct timex *") || strings.Contains(argTyp, "struct __kernel_timex *") {
		data := ctx.StrArgBuf[1024 : 1024+208]
		if ctx.Ret >= 0 || ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 208, true); err == nil && len(d) == 208 {
				data = d
			}
		}
		return format.Timex(data), true
	}

	if strings.Contains(argTyp, "struct stat *") || strings.Contains(argTyp, "struct stat64 *") || strings.Contains(argTyp, "struct new_stat *") || strings.Contains(argTyp, "struct __old_kernel_stat *") {
		if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
			return fmt.Sprintf("%#x", val), true
		}
		data := ctx.StrArgBuf[1024 : 1024+144]
		if ctx.Ret >= 0 || ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 144, true); err == nil && len(d) == 144 {
				data = d
			}
		}
		return format.Stat(data), true
	}

	return "", false
}

func (h *DefaultHandler) decodeKeyArg(ctx *Context, i int, argName string, val uint64) (string, bool) {
	scName := ctx.ScMeta.Name
	if strings.Contains(argName, "type") || strings.Contains(argName, "description") || strings.Contains(argName, "callout_info") {
		off := 0
		bufLen := 128
		if strings.Contains(argName, "description") {
			off = 64
		} else if strings.Contains(argName, "callout_info") {
			off = 256
			bufLen = 256
		}
		return ctx.Decoder.DecodeString(ctx.Tid, val, ctx.StrArgBuf[off:off+bufLen], ctx.ArgProbeRet(i), scName, ctx.Opts.StringLimit), true
	}

	if strings.Contains(argName, "payload") {
		plen := int(ctx.Args[3])
		if plen <= 0 {
			if plen == 0 {
				return "\"\"", true
			}
			return fmt.Sprintf("%#x", val), true
		}

		capLen := plen
		if capLen > 256 {
			capLen = 256
		}

		data := ctx.StrArgBuf[256 : 256+capLen]
		readSuccess := ctx.IsArgReadSuccess(2)
		if !readSuccess {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, capLen, false); err == nil && len(d) == capLen {
				data = d
				readSuccess = true
			}
		}

		if !readSuccess {
			return fmt.Sprintf("%#x", val), true
		}

		return format.Buffer(data, ctx.Opts.StringLimit, plen), true
	}
	return "", false
}

func (h *DefaultHandler) decodeBufferArg(ctx *Context, val uint64, res *Result) (string, bool) {
	scName := ctx.ScMeta.Name
	fd := int32(-1)
	if strings.Contains(scName, "read") || strings.Contains(scName, "write") {
		fd = int32(ctx.Args[0])
	}

	if (scName == "read" || scName == "pread64") && ctx.Ret > 0 && ctx.Opts.TraceReadFDs[fd] {
		szH := uint64(ctx.Ret)
		data := ctx.StrArgBuf[1024 : 1024+512]
		if ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, int(szH), true); err == nil {
				data = d
			}
		}
		res.HexDumpStr = format.Hexdump(data)
		return format.Buffer(data, ctx.Opts.StringLimit, int(szH)), true
	}

	if (scName == "write" || scName == "pwrite64") && ctx.Opts.TraceWriteFDs[fd] {
		szH := ctx.Args[2]
		data := ctx.StrArgBuf[0:512]
		if ctx.ProbeRetEnter < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, int(szH), true); err == nil {
				data = d
			}
		}
		res.HexDumpStr = format.Hexdump(data)
		return format.Buffer(data, ctx.Opts.StringLimit, int(szH)), true
	}

	return "", false
}

func (h *DefaultHandler) decodeRenArg(ctx *Context, i int, val uint64) (string, bool) {
	scName := ctx.ScMeta.Name
	var p string
	switch scName {
	case "rename", "link", "symlink":
		if i == 0 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[0], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, scName, 0)
		} else if i == 1 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[512:1024], ctx.ProbeRetEnter, scName, 0)
		}
	case "renameat", "renameat2", "linkat":
		if i == 1 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, scName, 0)
		} else if i == 3 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[3], ctx.StrArgBuf[512:1024], ctx.ProbeRetEnter, scName, 0)
		}
	case "symlinkat":
		if i == 0 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[0], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, scName, 0)
		} else if i == 2 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[2], ctx.StrArgBuf[512:1024], ctx.ProbeRetEnter, scName, 0)
		}
	}
	return p, true
}

// decodePointer formats pointer arguments, falling back to raw hex if needed.
// Impact: Specifically decodes output buffers (like readlink/readlinkat)
// or standard char* / void* strings. Modifying this impacts string output formats.
func (h *DefaultHandler) decodePointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool) {
	scName := ctx.ScMeta.Name
	if scName == "readlink" || scName == "readlinkat" {
		bufIdx := 1
		if scName == "readlinkat" {
			bufIdx = 2
		}
		if i == bufIdx {
			if ctx.Ret < 0 {
				return fmt.Sprintf("%#x", val), true
			}
			data := ctx.StrArgBuf[1024 : 1024+512]
			isEmpty := true
			for _, b := range data {
				if b != 0 {
					isEmpty = false
					break
				}
			}
			if ctx.ProbeRetExit < 0 || isEmpty {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, int(ctx.Ret), true); err == nil {
					data = d
				}
			}
			sz := int(ctx.Ret)
			if sz > len(data) {
				sz = len(data)
			}
			if sz < 0 {
				sz = 0
			}
			if idx := bytes.IndexByte(data[:sz], 0); idx != -1 {
				sz = idx
			}
			return format.BufferEscape(data[:sz], ctx.Opts.StringLimit, int(ctx.Ret), ctx.Decoder.HexEscapeMode), true
		}
	}

	if ctx.Ret < 0 && ctx.Ret >= -4095 {
		isStr := strings.Contains(argTyp, "char *")
		isPath := argName == "filename" || argName == "pathname" || argName == "path" || argName == "oldname" || argName == "newname"
		if !isPath && !isStr && !strings.Contains(argName, "type") && !strings.Contains(argName, "description") && !strings.Contains(argName, "payload") && !strings.Contains(argName, "callout_info") {
			return fmt.Sprintf("%#x", val), true
		}
	}

	if strings.Contains(argTyp, "char *") || strings.Contains(argTyp, "void *") {
		scName := ctx.ScMeta.Name

		if scName == "add_key" || scName == "request_key" {
			if p, ok := h.decodeKeyArg(ctx, i, argName, val); ok {
				return p, true
			}
		}

		if strings.Contains(scName, "read") || strings.Contains(scName, "write") {
			if p, ok := h.decodeBufferArg(ctx, val, res); ok {
				return p, true
			}
		}

		isRen := scName == "rename" || scName == "renameat" || scName == "renameat2" || scName == "link" || scName == "linkat" || scName == "symlink" || scName == "symlinkat"
		if isRen {
			if p, ok := h.decodeRenArg(ctx, i, val); ok {
				return p, true
			}
		}

		if strings.Contains(argTyp, "char *") {
			if val == ctx.Ptr && ctx.RawStrArg != "" && !strings.HasPrefix(ctx.RawStrArg, "0x") {
				return ctx.RawStrArg, true
			}
			limit := ctx.Opts.StringLimit
			isPath := argName == "filename" || argName == "pathname" || argName == "path" || argName == "oldname" || argName == "newname"
			if isPath {
				limit = 0
			}
			return ctx.Decoder.DecodeString(ctx.Pid, val, ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, scName, limit), true
		}

		return fmt.Sprintf("%#x", val), true
	}

	return "", false
}

func (h *DefaultHandler) decodeScalar(ctx *Context, argTyp, argName string, val uint64) string {
	if argTyp == "dev_t" {
		return format.Dev(val)
	}

	if (ctx.ScMeta.Name == "mknod" || ctx.ScMeta.Name == "mknodat") && strings.HasPrefix(argTyp, "umode_t") {
		return format.MknodMode(uint16(val))
	}

	// Decode uid_t/gid_t as 32-bit decimal, with 0xffffffff mapping to -1.
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
