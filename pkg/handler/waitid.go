package handler

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/meta"
)

func init() {
	h := &WaitidHandler{}
	Register("waitid", h)
}

type WaitidHandler struct{}

func (h *WaitidHandler) Handle(ctx *Context) Result {
	res := Result{}

	idtype := int32(ctx.Args[0])
	res.ArgParts = append(res.ArgParts, meta.DecodeFlags(uint64(idtype), "waitid_types"))

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[1])))

	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		if ctx.Args[2] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
	} else {
		res.ArgParts = append(res.ArgParts, decodeSiginfo(ctx, ctx.Args[2]))
	}

	res.ArgParts = append(res.ArgParts, meta.DecodeFlags(ctx.Args[3], "wait4_options"))

	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		if ctx.Args[4] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[4]))
		}
	} else {
		res.ArgParts = append(res.ArgParts, decodeRusage(ctx, ctx.Args[4]))
	}

	return res
}

func decodeSigchldCode(code int32) string {
	switch code {
	case 1: return "CLD_EXITED"
	case 2: return "CLD_KILLED"
	case 3: return "CLD_DUMPED"
	case 4: return "CLD_TRAPPED"
	case 5: return "CLD_STOPPED"
	case 6: return "CLD_CONTINUED"
	default: return fmt.Sprintf("%#x", code)
	}
}

func decodeSiginfo(ctx *Context, val uint64) string {
	if val == 0 {
		return "NULL"
	}
	data, ok := ctx.FetchStructDataExact(val, 48, true, nil)
	if !ok {
		return fmt.Sprintf("%#x", val)
	}

	si_signo := int32(binary.LittleEndian.Uint32(data[0:4]))
	si_code := int32(binary.LittleEndian.Uint32(data[8:12]))
	si_pid := int32(binary.LittleEndian.Uint32(data[16:20]))
	si_uid := int32(binary.LittleEndian.Uint32(data[20:24]))
	si_status := int32(binary.LittleEndian.Uint32(data[24:28]))
	si_utime := int64(binary.LittleEndian.Uint64(data[32:40]))
	si_stime := int64(binary.LittleEndian.Uint64(data[40:48]))

	if si_signo == 0 {
		return "{}"
	}

	signoStr := meta.DecodeFlags(uint64(si_signo), "signalnames")
	codeStr := decodeSigchldCode(si_code)
	
	statusStr := fmt.Sprintf("%d", si_status)
	if si_code != 1 {
		statusStr = meta.DecodeFlags(uint64(si_status), "signalnames")
	}

	return fmt.Sprintf("{si_signo=%s, si_code=%s, si_pid=%d, si_uid=%d, si_status=%s, si_utime=%d, si_stime=%d}",
		signoStr, codeStr, si_pid, si_uid, statusStr, si_utime, si_stime)
}

func decodeRusage(ctx *Context, val uint64) string {
	if val == 0 {
		return "NULL"
	}
	data, ok := ctx.FetchStructDataExact(val, 32, true, nil)
	if !ok {
		return fmt.Sprintf("%#x", val)
	}

	u_sec := int64(binary.LittleEndian.Uint64(data[0:8]))
	u_usec := int64(binary.LittleEndian.Uint64(data[8:16]))
	s_sec := int64(binary.LittleEndian.Uint64(data[16:24]))
	s_usec := int64(binary.LittleEndian.Uint64(data[24:32]))

	return fmt.Sprintf("{ru_utime={tv_sec=%d, tv_usec=%d}, ru_stime={tv_sec=%d, tv_usec=%d}, ...}",
		u_sec, u_usec, s_sec, s_usec)
}
