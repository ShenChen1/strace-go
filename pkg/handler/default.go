package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	SetDefault(&DefaultHandler{})
}

// DefaultHandler implements standard formatting for most syscall arguments.
type DefaultHandler struct{}

func (h *DefaultHandler) Handle(ctx *Context) Result {
	var res Result
	for i := 0; i < len(ctx.ScMeta.Args); i++ {
		argName, argTyp, val := ctx.ScMeta.Args[i], ctx.ScMeta.ArgTypes[i], ctx.Args[i]

		if ctx.ScMeta.Name == "brk" && i == 0 && val == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
			continue
		}

		if argName == "mode" && (ctx.ScMeta.Name == "open" || ctx.ScMeta.Name == "openat" || ctx.ScMeta.Name == "openat2") {
			fIdx := 1
			if ctx.ScMeta.Name == "openat" || ctx.ScMeta.Name == "openat2" { fIdx = 2 }
			fl := ctx.Args[fIdx]
			if (fl & 64) == 0 && (fl & 4194304) == 0 { continue }
		}

		if (ctx.ScMeta.Name == "stat" || ctx.ScMeta.Name == "fstat" || ctx.ScMeta.Name == "lstat" || ctx.ScMeta.Name == "newfstatat") && (argName == "statbuf" || argName == "ubuf") && ctx.Ret >= 0 {
			res.ArgParts = append(res.ArgParts, format.Stat(ctx.StrArgBuf[256:]))
			continue
		}

		if strings.Contains(argTyp, "*") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}
			if ctx.Ret < 0 && ctx.Ret >= -4095 && (argName != "filename" && argName != "pathname" && argName != "path" && argName != "oldname" && argName != "newname") {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				continue
			}

			if strings.Contains(argTyp, "char *") || strings.Contains(argTyp, "void *") {
				isRen := ctx.ScMeta.Name == "rename" || ctx.ScMeta.Name == "renameat" || ctx.ScMeta.Name == "renameat2" || ctx.ScMeta.Name == "link" || ctx.ScMeta.Name == "linkat" || ctx.ScMeta.Name == "symlink" || ctx.ScMeta.Name == "symlinkat"
				fd := int32(-1)
				if strings.Contains(ctx.ScMeta.Name, "read") || strings.Contains(ctx.ScMeta.Name, "write") { fd = int32(ctx.Args[0]) }

				if (ctx.ScMeta.Name == "read" && ctx.Ret > 0 && ctx.Opts.TraceReadFDs[fd]) || (ctx.ScMeta.Name == "write" && ctx.Opts.TraceWriteFDs[fd] && ctx.Ret >= 0) {
					szH := ctx.Args[2]
					if ctx.ScMeta.Name == "read" { szH = uint64(ctx.Ret) }
					full, _ := ctx.MemReader.ReadRobust(ctx.Tid, val, int(szH), true)
					if full == nil {
						capLen := int(szH)
						if capLen > 512 { capLen = 512 }
						if capLen < 0 { capLen = 0 }
						res.ArgParts = append(res.ArgParts, format.Buffer(ctx.StrArgBuf[:capLen], ctx.Opts.StringLimit, int(szH)))
					} else {
						res.HexDumpStr = format.Hexdump(full)
						res.ArgParts = append(res.ArgParts, format.Buffer(full, ctx.Opts.StringLimit, int(szH)))
					}
				} else if isRen {
					p1 := ctx.Decoder.DecodeString(ctx.Tid, ctx.Args[0], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, ctx.ScMeta.Name, 0)
					p2 := ctx.Decoder.DecodeString(ctx.Tid, ctx.Args[1], ctx.StrArgBuf[1024:1536], ctx.ProbeRetEnter, ctx.ScMeta.Name, 0)
					if ctx.ScMeta.Name != "rename" {
						p1 = ctx.Decoder.DecodeString(ctx.Tid, ctx.Args[1], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, ctx.ScMeta.Name, 0)
						p2 = ctx.Decoder.DecodeString(ctx.Tid, ctx.Args[3], ctx.StrArgBuf[1024:1536], ctx.ProbeRetEnter, ctx.ScMeta.Name, 0)
					}
					res.ArgParts = append(res.ArgParts, format.Buffer([]byte(p1), ctx.Opts.StringLimit, 0))
					if val != ctx.Args[0] && (ctx.ScMeta.Name == "rename" || val != ctx.Args[1]) {
						res.ArgParts[len(res.ArgParts)-1] = format.Buffer([]byte(p2), ctx.Opts.StringLimit, 0)
					}
				} else {
					res.ArgParts = append(res.ArgParts, format.Buffer([]byte(ctx.RawStrArg), ctx.Opts.StringLimit, 0))
				}
				continue
			}

			if strings.Contains(argTyp, "struct pollfd *") {
				nfds := uint32(ctx.Args[1])
				res.ArgParts = append(res.ArgParts, format.Pollfds(ctx.StrArgBuf[:512], nfds))
				continue
			}

			if strings.Contains(argTyp, "fd_set *") {
				n := int(ctx.Args[0])
				off := 0
				if argName == "outp" { off = 128 } else if argName == "exp" { off = 256 }
				res.ArgParts = append(res.ArgParts, format.FdSet(n, ctx.StrArgBuf[off:off+128]))
				continue
			}

			if strings.Contains(argTyp, "struct epoll_event *") {
				if ctx.ScMeta.Name == "epoll_ctl" {
					res.ArgParts = append(res.ArgParts, format.EpollEvent(ctx.StrArgBuf[:12]))
					continue
				}
				count := int(ctx.Ret)
				if count < 0 { count = 0 }
				res.ArgParts = append(res.ArgParts, format.EpollEvents(ctx.StrArgBuf[:512], count))
				continue
			}

			if scName := ctx.ScMeta.Name; scName == "adjtimex" && argName == "txc_p" && ctx.Ret >= 0 {
				sdata := ctx.StrArgBuf[512:768]
				if ctx.ProbeRetExit < 0 || (binary.LittleEndian.Uint32(sdata[40:44]) == 0 && binary.LittleEndian.Uint64(sdata[8:16]) == 0) {
					if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, 208, true); err == nil { sdata = d }
				}
				res.ArgParts = append(res.ArgParts, format.Timex(sdata))
				continue
			}

			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
			continue
		}

		if argName == "fd" || argName == "dfd" || strings.Contains(argName, "dfd") {
			if int32(val) == -100 {
				res.ArgParts = append(res.ArgParts, "AT_FDCWD")
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(val)))
			}
		} else if argName == "whence" {
			res.ArgParts = append(res.ArgParts, format.Whence(val))
		} else if xlatName, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name][argName]; ok {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, xlatName))
		} else if argName == "mode" || argName == "offset" {
			if argName == "mode" {
				s := fmt.Sprintf("%o", uint16(val))
				if len(s) < 3 { s = strings.Repeat("0", 3-len(s)) + s }
				if s[0] != '0' { s = "0" + s }
				res.ArgParts = append(res.ArgParts, s)
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(val)))
			}
		} else if strings.Contains(argTyp, "int") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "long") {
			if strings.Contains(argTyp, "unsigned") {
				if strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long") {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", uint32(val)))
				} else {
					if val > 0xffff {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
					} else {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", val))
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
