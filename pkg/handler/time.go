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
			data := ctx.StrArgBuf[BpfExitArgOffset : BpfExitArgOffset+16]
			if ctx.SysName == "clock_settime" {
				data = ctx.StrArgBuf[0:16]
			}
			readSuccess := ctx.ProbeRetExit >= 0
			if ctx.SysName == "clock_settime" { readSuccess = ctx.ProbeRetEnter >= 0 }

			if !readSuccess && ctx.Ret != -14 { // Not EFAULT
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ptr, 16, true); err == nil && len(d) == 16 {
					data = d
					readSuccess = true
				}
			}

			if readSuccess {
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

		data := ctx.StrArgBuf[BpfExitArgOffset : BpfExitArgOffset+208]
		if ctx.SysName == "adjtimex" {
			// adjtimex captures at 0 and 1024?
			// Actually capture_rules says 0 and 1024.
		}
		
		readSuccess := ctx.ProbeRetExit >= 0
		if ctx.Ret < 0 && ctx.Ret != -14 { // Not EFAULT
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ptr, 208, true); err == nil && len(d) == 208 {
				data = d
				readSuccess = true
			}
		}

		if readSuccess || ctx.Ret >= 0 {
			res.ArgParts = append(res.ArgParts, format.Timex(data))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		}
	}
	return res
}
