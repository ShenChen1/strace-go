package handler

import (
	"strace-go/pkg/format"
)

func init() {
	RegisterStructDecoder("struct timespec *", StructDecoderFunc(decodeTimespec))
	RegisterStructDecoder("struct __kernel_timespec *", StructDecoderFunc(decodeTimespec))
	RegisterStructDecoder("struct timeval *", StructDecoderFunc(decodeTimeval))
	RegisterStructDecoder("struct timex *", StructDecoderFunc(decodeTimex))
	RegisterStructDecoder("struct __kernel_timex *", StructDecoderFunc(decodeTimex))
	RegisterStructDecoder("struct itimerval *", StructDecoderFunc(decodeItimerval))
	RegisterStructDecoder("struct itimerspec *", StructDecoderFunc(decodeItimerspec))
	RegisterStructDecoder("struct timezone *", StructDecoderFunc(decodeTimezone))
}

func decodeTimespec(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "utimensat" {
		return ctx.DecodeStructWithFallback(val, 32, false, ctx.StrArgBuf[BpfMiscArgOffset:BpfMiscArgOffset+32], format.Utimes)
	}

	isNanosleep := ctx.ScMeta.Name == "nanosleep"
	isClockNanosleep := ctx.ScMeta.Name == "clock_nanosleep"
	if isNanosleep || isClockNanosleep {
		isOutParam := (isNanosleep && i == 1) || (isClockNanosleep && i == 3)
		if isOutParam {
			if ctx.Ret != -516 && ctx.Ret != -4 {
				return "", false
			}
			return ctx.DecodeStructWithFallback(val, 16, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+16], format.Timespec)
		} else {
			return ctx.DecodeStructWithFallback(val, 16, false, ctx.StrArgBuf[0:16], format.Timespec)
		}
	}

	if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
		d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, 16, false)
		if err == nil && len(d) == 16 {
			return format.Timespec(d), true
		}
	}
	
	return ctx.DecodeStructWithFallback(val, 16, false, ctx.StrArgBuf[0:16], format.Timespec)
}

func decodeTimeval(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := ctx.ScMeta.Name == "gettimeofday"
	if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
		d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false)
		if err == nil && len(d) == 16 {
			return format.Timeval(d), true
		}
	}
	if isOut {
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
			return ctx.DecodeStructWithFallback(val, 16, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+16], format.Timeval)
		}
		return "", false
	}
	return ctx.DecodeStructWithFallback(val, 16, false, ctx.StrArgBuf[0:16], format.Timeval)
}

func decodeTimex(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	return ctx.DecodeStructWithFallback(val, 208, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+208], format.Timex)
}

func decodeItimerval(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := ctx.ScMeta.Name == "getitimer" && i == 1 || ctx.ScMeta.Name == "setitimer" && i == 2
	if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
		d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 32, false)
		if err == nil && len(d) >= 32 {
			return format.Itimerval(d), true
		}
	}
	if isOut {
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
			return ctx.DecodeStructWithFallback(val, 32, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+32], format.Itimerval)
		}
		return "", false
	}
	return ctx.DecodeStructWithFallback(val, 32, false, ctx.StrArgBuf[0:32], format.Itimerval)
}

func decodeItimerspec(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := (ctx.ScMeta.Name == "timerfd_gettime" && i == 1) || (ctx.ScMeta.Name == "timerfd_settime" && i == 3) || (ctx.ScMeta.Name == "timer_gettime" && i == 1) || (ctx.ScMeta.Name == "timer_settime" && i == 3)
	if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
		d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 32, false)
		if err == nil && len(d) >= 32 {
			return format.Itimerspec(d), true
		}
	}
	if isOut {
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
			return ctx.DecodeStructWithFallback(val, 32, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+32], format.Itimerspec)
		}
		return "", false
	}
	return ctx.DecodeStructWithFallback(val, 32, false, ctx.StrArgBuf[0:32], format.Itimerspec)
}

func decodeTimezone(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := ctx.ScMeta.Name == "gettimeofday" && i == 1
	if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
		d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 8, false)
		if err == nil && len(d) >= 8 {
			return format.Timezone(d), true
		}
	}
	if isOut {
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
			return ctx.DecodeStructWithFallback(val, 8, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+8], format.Timezone)
		}
		return "", false
	}
	return ctx.DecodeStructWithFallback(val, 8, false, ctx.StrArgBuf[0:8], format.Timezone)
}
