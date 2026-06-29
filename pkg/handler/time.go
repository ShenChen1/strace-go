package handler

import (
	"fmt"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &TimeHandler{}
	Register("adjtimex", h)
	Register("clock_adjtime", h)
	Register("clock_gettime", h)
	Register("clock_settime", h)
	Register("clock_getres", h)
}

type TimeHandler struct{}

const (
	timespecSize = 16
	timexSize    = 208
)

func (h *TimeHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "clock_gettime", "clock_settime", "clock_getres":
		clockId := int32(ctx.Args[0])
		res.ArgParts = append(res.ArgParts, meta.DecodeFlags(uint64(clockId), "clocknames"))

		ptr := ctx.Args[1]
		if ptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			var data []byte
			var ok bool
			if ctx.SysName == "clock_settime" {
				data, ok = ctx.EnterArgSnapshot(1, BpfEnterArgOffset, timespecSize)
			} else {
				data, ok = ctx.ExitSnapshot(BpfExitArgOffset, timespecSize)
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
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(uint64(clockId), "clocknames"))
			ptr = ctx.Args[1]
		}

		if ptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
			return res
		}

		data, ok := ctx.ExitSnapshot(BpfExitArgOffset, timexSize)
		if ok {
			res.ArgParts = append(res.ArgParts, format.Timex(data))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		}
	}
	return res
}
