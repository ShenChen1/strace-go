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

const (
	cachestatRangeSize = 16
	cachestatStatsSize = 40
	cachestatRangeOff  = BpfMiscArgOffset
	cachestatStatsOff  = BpfExitArgOffset
)

func (h *CachestatHandler) Handle(ctx *Context) Result {
	res := Result{}
	res.ArgParts = append(res.ArgParts, h.formatFdArg(ctx, "fd", ctx.Args[0])) // fd

	// cstat_range
	if ctx.Args[1] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		if d, ok := cachestatStructSnapshot(ctx, 1, PayloadDirectionIn, cachestatRangeOff, cachestatRangeSize); ok {
			res.ArgParts = append(res.ArgParts, formatCachestatRange(d))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	}

	// cstat
	if ctx.Args[2] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		if ctx.Ret >= 0 {
			if d, ok := cachestatStructSnapshot(ctx, 2, PayloadDirectionOut, cachestatStatsOff, cachestatStatsSize); ok {
				res.ArgParts = append(res.ArgParts, formatCachestatStats(d))
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

func cachestatStructSnapshot(
	ctx *Context,
	argIndex int,
	direction PayloadDirection,
	offset int,
	size int,
) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, direction); ok && len(data) >= size {
		return data[:size], true
	}
	if direction == PayloadDirectionOut {
		return ctx.ExitSnapshot(offset, size)
	}
	return ctx.EnterArgSnapshot(argIndex, offset, size)
}

func formatCachestatRange(d []byte) string {
	return fmt.Sprintf("{off=%#x, len=%d}", binary.LittleEndian.Uint64(d[0:8]), binary.LittleEndian.Uint64(d[8:16]))
}

func formatCachestatStats(d []byte) string {
	return fmt.Sprintf("{nr_cache=%d, nr_dirty=%d, nr_writeback=%d, nr_evicted=%d, nr_recently_evicted=%d}",
		binary.LittleEndian.Uint64(d[0:8]),
		binary.LittleEndian.Uint64(d[8:16]),
		binary.LittleEndian.Uint64(d[16:24]),
		binary.LittleEndian.Uint64(d[24:32]),
		binary.LittleEndian.Uint64(d[32:40]))
}
