package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

func init() {
	Register("io_setup", &AioHandler{})
	Register("io_destroy", &AioHandler{})
	Register("io_submit", &AioHandler{})
	Register("io_cancel", &AioHandler{})
	Register("io_getevents", &AioHandler{})
	Register("io_pgetevents", &AioHandler{})
	Register("io_pgetevents_time64", &AioHandler{})
}

type AioHandler struct{}

func (h *AioHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "io_setup":
		h.formatIoSetup(ctx, &res)
	case "io_destroy":
		h.formatIoDestroy(ctx, &res)
	case "io_submit":
		h.formatIoSubmit(ctx, &res)
	case "io_cancel":
		h.formatIoCancel(ctx, &res)
	case "io_getevents", "io_pgetevents", "io_pgetevents_time64":
		h.formatIoGetevents(ctx, &res)
	}
	return res
}

func (h *AioHandler) formatIoSetup(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", uint32(ctx.Args[0])))
	if ctx.Args[1] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else if ctx.Ret >= 0 {
		data, ok := ctx.FetchStructDataExact(ctx.Args[1], 8, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+8])
		if ok {
			res.ArgParts = append(res.ArgParts, "["+fmt.Sprintf("%#x", binary.LittleEndian.Uint64(data))+"]")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
	}
}

func (h *AioHandler) formatIoDestroy(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
}

func (h *AioHandler) formatIoSubmit(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[1])))
	count := int(ctx.Args[1])
	if ctx.Args[2] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
		return
	}
	if count <= 0 {
		if count == 0 {
			res.ArgParts = append(res.ArgParts, "[]")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
		return
	}

	limit := 16
	pdata := ctx.StrArgBuf[0:512]
	readSuccess := ctx.ProbeRetEnter >= 0
	if !readSuccess {
		d, _ := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[2], count*8, true)
		if len(d) > 0 {
			pdata = d
			readSuccess = true
		}
	}

	if !readSuccess {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		return
	}

	var parts []string
	var i int
	for i = 0; i < count && i < limit; i++ {
		if len(pdata) < (i+1)*8 { break }
		p := binary.LittleEndian.Uint64(pdata[i*8 : i*8+8])
		if p == 0 { parts = append(parts, "NULL"); continue }

		var idata []byte
		if i < 2 && ctx.ProbeRetEnter >= 0 {
			idata = ctx.StrArgBuf[512+i*64 : 512+(i+1)*64]
			allZeros := true
			for _, x := range idata {
				if x != 0 { allZeros = false; break }
			}
			if allZeros { idata = nil }
		}

		if idata == nil {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, p, 64, true); err == nil && len(d) > 0 {
				idata = d
			}
		}

		if idata != nil {
			parts = append(parts, format.Iocb(idata, ctx.Opts.Verbose, func(opcode uint16, buf uint64, nbytes uint64) string {
				return h.formatAioBuf(ctx, opcode, buf, nbytes)
			}))
		} else {
			parts = append(parts, fmt.Sprintf("%#x", p))
		}
	}
	if count > i {
		parts = append(parts, "...")
		parts[len(parts)-1] += fmt.Sprintf(" /* %#x */", ctx.Args[2]+uint64(i*8))
	}
	res.ArgParts = append(res.ArgParts, "["+strings.Join(parts, ", ")+"]")
}

func (h *AioHandler) formatAioBuf(ctx *Context, opcode uint16, buf uint64, nbytes uint64) string {
	if buf == 0 {
		if opcode == 7 || opcode == 8 {
			return "NULL"
		} else {
			return "0"
		}
	}
	if opcode == 1 {
		// IOCB_CMD_PWRITE: print string
		data, err := ctx.MemReader.ReadRobust(ctx.Pid, buf, int(nbytes), false)
		if err == nil && len(data) > 0 {
			return format.Buffer(data, ctx.Opts.StringLimit, int(nbytes))
		}
		return fmt.Sprintf("%#x", buf)
	}
	if opcode != 7 && opcode != 8 {
		return fmt.Sprintf("%#x", buf)
	}
	data, err := ctx.MemReader.ReadRobust(ctx.Pid, buf, int(nbytes)*16, false)
	if err != nil || len(data) == 0 {
		return fmt.Sprintf("%#x", buf)
	}
	return format.IovecArray(data, int(nbytes))
}

func (h *AioHandler) formatIoCancel(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	if ctx.Args[1] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		data := ctx.StrArgBuf[0:64]
		readSuccess := ctx.ProbeRetEnter >= 0
		if !readSuccess {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[1], 64, true); err == nil && len(d) > 0 {
				data = d
				readSuccess = true
			}
		}
		if readSuccess {
			res.ArgParts = append(res.ArgParts, format.Iocb(data, ctx.Opts.Verbose, func(opcode uint16, buf uint64, nbytes uint64) string {
				return h.formatAioBuf(ctx, opcode, buf, nbytes)
			}))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	}
	if ctx.Args[2] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
	}
}

func (h *AioHandler) formatIoGetevents(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[1])))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[2])))
	
	if ctx.Args[3] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else if ctx.Ret > 0 {
		count := int(ctx.Ret)
		data, ok := ctx.FetchStructData(ctx.Args[3], count*32, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+512])
		if ok {
			res.ArgParts = append(res.ArgParts, format.IoEvents(data, count))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[3]))
		}
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[3]))
	}

	if ctx.Args[4] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		data, ok := ctx.FetchArgStructDataExact(4, ctx.Args[4], 16, false, ctx.StrArgBuf[512:528])
		if ok {
			allZeros := true
			for _, x := range data {
				if x != 0 { allZeros = false; break }
			}
			if allZeros && ctx.Ret < 0 {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[4]))
			} else {
				res.ArgParts = append(res.ArgParts, format.Timespec(data))
			}
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[4]))
		}
	}

	name := ctx.SysName
	if strings.Contains(name, "pgetevents") {
		if ctx.Args[5] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			d, ok := ctx.FetchArgStructDataExact(5, ctx.Args[5], 16, false, ctx.StrArgBuf[528:544])
			if ok {
				allZerosSig := true
				for _, x := range d {
					if x != 0 { allZerosSig = false; break }
				}
				if allZerosSig && ctx.Ret < 0 {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[5]))
				} else {
					sigmask := binary.LittleEndian.Uint64(d[0:8])
					sigsetsize := binary.LittleEndian.Uint64(d[8:16])
					sigsetStr := fmt.Sprintf("%#x", sigmask)
					if sigsetsize <= 8 && sigsetsize > 0 {
						var maskData []byte
						// If BPF successfully captured arg 5 (bit 5 in ProbeRetEnter is not set)
						arg5Failed := false
						if ctx.ProbeRetEnter < -1 {
							mask := uint32(-ctx.ProbeRetEnter - 1)
							if (mask & (1 << 5)) != 0 {
								arg5Failed = true
							}
						} else if ctx.ProbeRetEnter == -1 {
							arg5Failed = true
						}

						if !arg5Failed && len(ctx.StrArgBuf) >= 544+int(sigsetsize) {
							maskData = ctx.StrArgBuf[544 : 544+int(sigsetsize)]
						}
						
						if arg5Failed || maskData == nil {
							if m, err := ctx.MemReader.ReadRobust(ctx.Tid, sigmask, int(sigsetsize), false); err == nil {
								maskData = m
							}
						}

						if maskData != nil {
							if s := format.Sigset(maskData); s != "" {
								sigsetStr = s
							}
						}
					}
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("{sigmask=%s, sigsetsize=%d}", sigsetStr, sigsetsize))
				}
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[5]))
			}
		}
	}
}
