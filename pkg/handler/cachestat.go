package handler

import (
	"encoding/binary"
	"fmt"

)

func init() {
	h := &CachestatHandler{}
	Register("cachestat", h)
}

type CachestatHandler struct {
	DefaultHandler
}

func (h *CachestatHandler) Handle(ctx *Context) Result {
	res := Result{}
	res.ArgParts = append(res.ArgParts, h.formatFdArg(ctx, "fd", ctx.Args[0])) // fd

	// cstat_range
	if ctx.Args[1] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		var d []byte
		if len(ctx.StrArgBuf) >= 512+16 {
			d = ctx.StrArgBuf[512 : 512+16]
		}
		if len(d) != 16 || (ctx.ProbeRetEnter < 0 && d[0] == 0 && d[15] == 0) {
			d, _ = ctx.MemReader.ReadRobust(ctx.Tid, ctx.Args[1], 16, false)
		}
		if len(d) == 16 {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("{off=%#x, len=%d}", binary.LittleEndian.Uint64(d[0:8]), binary.LittleEndian.Uint64(d[8:16])))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	}

	// cstat
	if ctx.Args[2] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
			d, err := ctx.MemReader.ReadRobust(ctx.Tid, ctx.Args[2], 40, true)
			if err == nil && len(d) == 40 {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("{nr_cache=%d, nr_dirty=%d, nr_writeback=%d, nr_evicted=%d, nr_recently_evicted=%d}",
					binary.LittleEndian.Uint64(d[0:8]),
					binary.LittleEndian.Uint64(d[8:16]),
					binary.LittleEndian.Uint64(d[16:24]),
					binary.LittleEndian.Uint64(d[24:32]),
					binary.LittleEndian.Uint64(d[32:40])))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
			}
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
	}

	flagsStr := h.decodeScalar(ctx, "unsigned int", "flags", ctx.Args[3])
	if flagsStr == "4294967295" {
		flagsStr = "0xffffffff"
	}
	res.ArgParts = append(res.ArgParts, flagsStr) // flags

	return res
}
