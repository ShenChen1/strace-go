package handler

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/format"
)

func registerBuiltinTime(r *Registry) {
	h := &TimeHandler{}
	r.Register("time", h)
	r.Register("adjtimex", h)
	r.Register("clock_adjtime", h)
	r.Register("clock_gettime", h)
	r.Register("clock_settime", h)
	r.Register("clock_getres", h)
}

type TimeHandler struct{}

const (
	timespecSize = 16
	timexSize    = 208
)

func (h *TimeHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "time":
		return handleTimeSyscall(ctx)
	case "clock_gettime", "clock_settime", "clock_getres":
		clockId := int32(ctx.Args[0])
		res.ArgParts = append(res.ArgParts, decodeFlags(ctx, uint64(clockId), "clocknames"))

		ptr := ctx.Args[1]
		if ptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			var data []byte
			var ok bool
			if ctx.SysName == "clock_settime" {
				data, ok = timeHandlerStructSnapshot(ctx, 1, PayloadDirectionIn, timespecSize)
			} else {
				data, ok = timeHandlerStructSnapshot(ctx, 1, PayloadDirectionOut, timespecSize)
			}

			if ok {
				res.ArgParts = append(res.ArgParts, format.Timespec(data))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
			}
		}
	case "adjtimex", "clock_adjtime":
		ptr := ctx.Args[0]
		if ctx.SysName == "clock_adjtime" {
			clockId := int32(ctx.Args[0])
			res.ArgParts = append(res.ArgParts, decodeFlags(ctx, uint64(clockId), "clocknames"))
			ptr = ctx.Args[1]
		}

		if ptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
			return res
		}

		data, ok := timeHandlerStructSnapshot(ctx, timeHandlerTimexArg(ctx), PayloadDirectionOut, timexSize)
		if ok {
			res.ArgParts = append(res.ArgParts, format.TimexWithCatalog(catalogForContext(ctx), data))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		}
	}
	return res
}

func handleTimeSyscall(ctx *Context) Result {
	res := Result{}
	ptr := ctx.Args[0]
	if ptr == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else if data, ok := timeHandlerStructSnapshot(ctx, 0, PayloadDirectionOut, 8); ok &&
		ctx.Ret >= 0 && len(data) >= 8 {
		sec := int64(binary.LittleEndian.Uint64(data[:8]))
		res.ArgParts = append(res.ArgParts, "["+format.TimeT(sec)+"]")
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
	}
	if ctx.Ret >= 0 {
		res.ReturnDesc = format.TimeTDescription(ctx.Ret)
	}
	return res
}

func timeHandlerTimexArg(ctx *Context) int {
	if ctx.SysName == "clock_adjtime" {
		return 1
	}
	return 0
}

func timeHandlerStructSnapshot(
	ctx *Context,
	argIndex int,
	direction PayloadDirection,
	size int,
) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, direction); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}
