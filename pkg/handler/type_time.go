package handler

import (
	"fmt"

	"strace-go/pkg/format"
)

func init() {
	RegisterStructDecoder("struct timespec *", StructDecoderFunc(decodeTimespec))
	RegisterStructDecoder("struct __kernel_timespec *", StructDecoderFunc(decodeTimespec))
	RegisterStructDecoder("struct timeval *", StructDecoderFunc(decodeTimeval))
	RegisterStructDecoder("struct timex *", StructDecoderFunc(decodeTimex))
	RegisterStructDecoder("struct __kernel_timex *", StructDecoderFunc(decodeTimex))
}

func decodeTimespec(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "utimensat" {
		data, ok := ctx.FetchStructDataExact(val, 32, false, ctx.StrArgBuf[512:512+32])
		if !ok {
			return fmt.Sprintf("%#x", val), true
		}
		return format.Utimes(data), true
	}

	isNanosleep := ctx.ScMeta.Name == "nanosleep"
	isClockNanosleep := ctx.ScMeta.Name == "clock_nanosleep"
	if isNanosleep || isClockNanosleep {
		isOutParam := (isNanosleep && i == 1) || (isClockNanosleep && i == 3)
		if isOutParam {
			if ctx.Ret != -516 && ctx.Ret != -4 {
				return "", false
			}
			d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, true)
			if err != nil || len(d) != 16 {
				return fmt.Sprintf("%#x", val), true
			}
			return format.Timespec(d), true
		} else {
			data, ok := ctx.FetchStructDataExact(val, 16, false, ctx.StrArgBuf[0:16])
			if !ok {
				return fmt.Sprintf("%#x", val), true
			}
			return format.Timespec(data), true
		}
	}

	if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
		d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false)
		if err == nil && len(d) == 16 {
			return format.Timespec(d), true
		}
	}
	
	data, ok := ctx.FetchStructDataExact(val, 16, false, ctx.StrArgBuf[0:16])
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Timespec(data), true
}

func decodeTimeval(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
		d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false)
		if err == nil && len(d) == 16 {
			return format.Timeval(d), true
		}
	}
	
	data, ok := ctx.FetchStructDataExact(val, 16, false, ctx.StrArgBuf[1024:1024+16])
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Timeval(data), true
}

func decodeTimex(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	data, ok := ctx.FetchStructDataExact(val, 208, true, ctx.StrArgBuf[1024:1024+208])
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Timex(data), true
}
