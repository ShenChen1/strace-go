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
}

type AioHandler struct{}

func (h *AioHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "io_setup":
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", uint32(ctx.Args[0])))
		if ctx.Args[1] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else if ctx.Ret >= 0 {
			data := ctx.StrArgBuf[1024:1032]
			if ctx.ProbeRetExit < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[1], 8, true); err == nil { data = d }
			}
			res.ArgParts = append(res.ArgParts, "["+fmt.Sprintf("%#x", binary.LittleEndian.Uint64(data))+"]")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	case "io_destroy":
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	case "io_submit":
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[1])))
		count := int(ctx.Args[1])
		if ctx.Args[2] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else if count > 0 {
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
				return res
			}

			var parts []string
			for i := 0; i < count && i < limit; i++ {
				if len(pdata) < (i+1)*8 { break }
				p := binary.LittleEndian.Uint64(pdata[i*8 : i*8+8])
				if p == 0 { parts = append(parts, "NULL"); continue }
				
				var idata []byte
				if i < 2 && ctx.ProbeRetEnter >= 0 {
					idata = ctx.StrArgBuf[512+i*64 : 512+(i+1)*64]
					allZeros := true; for _, x := range idata { if x != 0 { allZeros = false; break } }
					if allZeros { idata = nil }
				}
				
				if idata == nil {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, p, 64, true); err == nil && len(d) == 64 { idata = d }
				}
				
				if idata != nil {
					parts = append(parts, format.Iocb(idata, ctx.Opts.Verbose))
				} else {
					parts = append(parts, fmt.Sprintf("%#x", p))
				}
			}
			if count > limit {
				parts = append(parts, "...")
				parts[len(parts)-1] += fmt.Sprintf(" /* %#x */", ctx.Args[2] + uint64(limit*8))
			}
			res.ArgParts = append(res.ArgParts, "["+strings.Join(parts, ", ")+"]")
		} else if count == 0 {
			res.ArgParts = append(res.ArgParts, "[]")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
	case "io_cancel":
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
		if ctx.Args[1] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			data := ctx.StrArgBuf[0:64]
			readSuccess := ctx.ProbeRetEnter >= 0
			if !readSuccess {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[1], 64, true); err == nil && len(d) == 64 { 
					data = d
					readSuccess = true
				}
			}
			if readSuccess {
				res.ArgParts = append(res.ArgParts, format.Iocb(data, ctx.Opts.Verbose))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
			}
		}
		if ctx.Args[2] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
	case "io_getevents":
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[1])))
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[2])))
		if ctx.Args[3] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else if ctx.Ret > 0 {
			count := int(ctx.Ret)
			data := ctx.StrArgBuf[1024 : 1024+512]
			if ctx.ProbeRetExit < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[3], count*32, true); err == nil { data = d }
			}
			res.ArgParts = append(res.ArgParts, format.IoEvents(data, count))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[3]))
		}
		// Timeout
		if ctx.Args[4] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			data := ctx.StrArgBuf[512:528]
			if ctx.ProbeRetEnter < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[4], 16, false); err == nil { data = d }
			}
			allZeros := true; for _, x := range data { if x != 0 { allZeros = false; break } }
			if allZeros && ctx.Ret < 0 {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[4]))
			} else {
				res.ArgParts = append(res.ArgParts, format.Timespec(data))
			}
		}
	}
	return res
}
