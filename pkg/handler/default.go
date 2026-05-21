package handler

import (
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

	argCount := len(ctx.ScMeta.ArgTypes)
	if ctx.ScMeta.Name == "open" || ctx.ScMeta.Name == "openat" {
		flags := uint32(ctx.Args[1])
		if ctx.ScMeta.Name == "openat" { flags = uint32(ctx.Args[2]) }
		hasMode := (flags&0100 != 0) || (flags&020000000 != 0) // O_CREAT or O_TMPFILE
		if !hasMode {
			if ctx.ScMeta.Name == "open" { argCount = 2 } else { argCount = 3 }
		}
	}

	for i := 0; i < argCount; i++ {
		argTyp := ctx.ScMeta.ArgTypes[i]
		argName := ctx.ScMeta.Args[i]
		val := ctx.Args[i]

		// Handle XLATs
		if syscallMap, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name]; ok {
			if xlatName, ok := syscallMap[argName]; ok {
				res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, xlatName))
				continue
			}
		}

		if strings.Contains(argTyp, "*") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}

			// Priority decoding for well-known structs
			if strings.Contains(argTyp, "struct timespec *") || strings.Contains(argTyp, "struct __kernel_timespec *") {
				off := 0
				data := ctx.StrArgBuf[off : off+16]
				if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 || ctx.ScMeta.Name == "nanosleep" || ctx.ScMeta.Name == "clock_nanosleep" {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false); err == nil && len(d) == 16 { data = d }
				}
				res.ArgParts = append(res.ArgParts, format.Timespec(data))
				continue
			}

			if strings.Contains(argTyp, "struct timeval *") {
				data := ctx.StrArgBuf[1024 : 1024+16]
				if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false); err == nil && len(d) == 16 { data = d }
				}
				res.ArgParts = append(res.ArgParts, format.Timeval(data))
				continue
			}

			if strings.Contains(argTyp, "struct timex *") || strings.Contains(argTyp, "struct __kernel_timex *") {
				data := ctx.StrArgBuf[1024 : 1024+208]
				if ctx.Ret >= 0 || ctx.ProbeRetExit < 0 {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 208, true); err == nil && len(d) == 208 { data = d }
				}
				res.ArgParts = append(res.ArgParts, format.Timex(data))
				continue
			}

			if strings.Contains(argTyp, "struct stat *") || strings.Contains(argTyp, "struct stat64 *") || strings.Contains(argTyp, "struct new_stat *") || strings.Contains(argTyp, "struct __old_kernel_stat *") {
				if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
					continue
				}
				data := ctx.StrArgBuf[1024 : 1024+144]
				if ctx.Ret >= 0 || ctx.ProbeRetExit < 0 {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 144, true); err == nil && len(d) == 144 { data = d }
				}
				res.ArgParts = append(res.ArgParts, format.Stat(data))
				continue
			}

			// Fallback to strings or hex pointers
			if ctx.Ret < 0 && ctx.Ret >= -4095 {
				isStr := strings.Contains(argTyp, "char *")
				isPath := argName == "filename" || argName == "pathname" || argName == "path" || argName == "oldname" || argName == "newname"
				if !isPath && !isStr && !strings.Contains(argName, "type") && !strings.Contains(argName, "description") && !strings.Contains(argName, "payload") {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
					continue
				}
			}

			if strings.Contains(argTyp, "char *") || strings.Contains(argTyp, "void *") {
				isRen := ctx.ScMeta.Name == "rename" || ctx.ScMeta.Name == "renameat" || ctx.ScMeta.Name == "renameat2" || ctx.ScMeta.Name == "link" || ctx.ScMeta.Name == "linkat" || ctx.ScMeta.Name == "symlink" || ctx.ScMeta.Name == "symlinkat"

				if scName := ctx.ScMeta.Name; (scName == "add_key" || scName == "request_key") && (strings.Contains(argName, "type") || strings.Contains(argName, "description")) {
					off := 0
					if strings.Contains(argName, "description") { off = 64 }
					p := ctx.Decoder.DecodeString(ctx.Tid, val, ctx.StrArgBuf[off:off+128], ctx.ProbeRetEnter, scName, ctx.Opts.StringLimit)
					res.ArgParts = append(res.ArgParts, p)
					continue
				}
				if scName := ctx.ScMeta.Name; (scName == "add_key" || scName == "request_key") && strings.Contains(argName, "payload") {
					plen := int(ctx.Args[3])
					if plen <= 0 { 
						if plen == 0 { res.ArgParts = append(res.ArgParts, "\"\"") } else { res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val)) }
						continue
					}

					capLen := plen
					if capLen > 256 { capLen = 256 }

					data := ctx.StrArgBuf[256 : 256+capLen]
					readSuccess := ctx.ProbeRetEnter >= 0
					if !readSuccess {
						if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, capLen, false); err == nil && len(d) == capLen { 
							data = d
							readSuccess = true
						}
					}

					if !readSuccess {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
						continue
					}

					res.ArgParts = append(res.ArgParts, format.Buffer(data, ctx.Opts.StringLimit, plen))
					continue
				}

				fd := int32(-1)
				if strings.Contains(ctx.ScMeta.Name, "read") || strings.Contains(ctx.ScMeta.Name, "write") { fd = int32(ctx.Args[0]) }

				if (ctx.ScMeta.Name == "read" || ctx.ScMeta.Name == "pread64") && ctx.Ret > 0 && ctx.Opts.TraceReadFDs[fd] {
					szH := uint64(ctx.Ret)
					data := ctx.StrArgBuf[1024 : 1024+512]
					if ctx.ProbeRetExit < 0 {
						if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, int(szH), true); err == nil { data = d }
					}
					res.HexDumpStr = format.Hexdump(data)
					res.ArgParts = append(res.ArgParts, format.Buffer(data, ctx.Opts.StringLimit, int(szH)))
				} else if (ctx.ScMeta.Name == "write" || ctx.ScMeta.Name == "pwrite64") && ctx.Opts.TraceWriteFDs[fd] {
					szH := ctx.Args[2]
					data := ctx.StrArgBuf[0:512]
					if ctx.ProbeRetEnter < 0 {
						if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, int(szH), true); err == nil { data = d }
					}
					res.HexDumpStr = format.Hexdump(data)
					res.ArgParts = append(res.ArgParts, format.Buffer(data, ctx.Opts.StringLimit, int(szH)))
				} else if isRen {
					p1 := ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[0], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, ctx.ScMeta.Name, ctx.Opts.StringLimit)
					p2 := ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[512:1024], ctx.ProbeRetEnter, ctx.ScMeta.Name, ctx.Opts.StringLimit)
					if ctx.ScMeta.Name == "renameat" || ctx.ScMeta.Name == "renameat2" || ctx.ScMeta.Name == "linkat" {
						p1 = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, ctx.ScMeta.Name, ctx.Opts.StringLimit)
						p2 = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[3], ctx.StrArgBuf[512:1024], ctx.ProbeRetEnter, ctx.ScMeta.Name, ctx.Opts.StringLimit)
					}
					res.ArgParts = append(res.ArgParts, p1)
					if val != ctx.Args[0] && (ctx.ScMeta.Name == "rename" || val != ctx.Args[1]) {
						res.ArgParts[len(res.ArgParts)-1] = p2
					}
				} else if strings.Contains(argTyp, "char *") {
					res.ArgParts = append(res.ArgParts, ctx.Decoder.DecodeString(ctx.Pid, val, nil, -1, ctx.ScMeta.Name, ctx.Opts.StringLimit))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				}
				continue
			}

			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
			continue
		}

		if argName == "fd" || argName == "dfd" || strings.Contains(argName, "dfd") {
			if int32(val) == -100 {
				s := "AT_FDCWD"
				if ctx.Opts.ShowPaths {
					if l, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ctx.Pid)); err == nil {
						s += "<" + l + ">"
					}
				}
				res.ArgParts = append(res.ArgParts, s)
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(val)))
			}
		} else if argName == "whence" {
			res.ArgParts = append(res.ArgParts, format.Whence(val))
		} else if strings.HasPrefix(argTyp, "mode_t") || strings.HasPrefix(argTyp, "umode_t") {
			m := uint32(val)
			if strings.HasPrefix(argTyp, "umode_t") { m = uint32(uint16(val)) }
			s := fmt.Sprintf("%o", m)
			if len(s) < 3 { s = strings.Repeat("0", 3-len(s)) + s }
			if s[0] != '0' { s = "0" + s }
			res.ArgParts = append(res.ArgParts, s)
		} else if strings.Contains(argTyp, "int") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "long") || strings.Contains(argTyp, "aio_context_t") || strings.Contains(argTyp, "key_serial_t") {
			if strings.Contains(argTyp, "unsigned") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "aio_context_t") {
				if (strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long")) || argTyp == "unsigned" {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", uint32(val)))
				} else if strings.Contains(argTyp, "aio_context_t") {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				} else {
					if val > 0xffffffff {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", val))
					} else {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", uint32(val)))
					}
				}
			} else {
				if strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long") {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(val)))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(val)))
				}
			}
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
		}
	}
	return res
}
