package handler

import (
	"fmt"

	"strace-go/pkg/format"
)

func init() {
	Register("adjtimex", &TimeHandler{})
	Register("clock_adjtime", &TimeHandler{})
}

type TimeHandler struct{}

func (h *TimeHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "adjtimex", "clock_adjtime":
		ptr := ctx.Args[0]
		if ctx.SysName == "clock_adjtime" { ptr = ctx.Args[1] }
		
		if ptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
			return res
		}

		data := ctx.StrArgBuf[1024 : 1024+208]
		allZeros := true; for _, x := range data { if x != 0 { allZeros = false; break } }
		
		// If exit capture failed or was all zeros, try entry capture as fallback
		if ctx.ProbeRetExit < 0 || allZeros {
			entryData := ctx.StrArgBuf[0:208]
			allZerosEntry := true; for _, x := range entryData { if x != 0 { allZerosEntry = false; break } }
			if !allZerosEntry { data = entryData }
		}

		// Always try memory read if syscall succeeded and BPF capture was suspicious
		allZeros = true; for _, x := range data { if x != 0 { allZeros = false; break } }
		if ctx.Ret >= 0 && (allZeros || ctx.ProbeRetExit < 0) {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ptr, 208, true); err == nil { data = d }
		}

		if ctx.SysName == "clock_adjtime" {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
		}
		res.ArgParts = append(res.ArgParts, format.Timex(data))
	}
	return res
}
