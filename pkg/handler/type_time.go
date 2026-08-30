package handler

import (
	"strace-go/pkg/format"
)

func registerBuiltinTypeTime(r *Registry) {
	r.RegisterStructDecoder("struct timespec *", StructDecoderFunc(decodeTimespec))
	r.RegisterStructDecoder("struct __kernel_timespec *", StructDecoderFunc(decodeTimespec))
	r.RegisterStructDecoder("struct timeval *", StructDecoderFunc(decodeTimeval))
	r.RegisterStructDecoder("struct __kernel_old_timeval *", StructDecoderFunc(decodeTimeval))
	r.RegisterStructDecoder("struct utimbuf *", StructDecoderFunc(decodeUtimbuf))
	r.RegisterStructDecoder("struct timex *", StructDecoderFunc(decodeTimex))
	r.RegisterStructDecoder("struct __kernel_timex *", StructDecoderFunc(decodeTimex))
	r.RegisterStructDecoder("struct itimerval *", StructDecoderFunc(decodeItimerval))
	r.RegisterStructDecoder("struct itimerspec *", StructDecoderFunc(decodeItimerspec))
	r.RegisterStructDecoder("struct timezone *", StructDecoderFunc(decodeTimezone))
}

func decodeTimespec(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "utimensat" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, 32), func(data []byte) string {
			return format.UtimesWithXlat(data, xlatFormat(ctx))
		})
	}
	if ctx.ScMeta.Name == "futex_wait" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, timespecSize), format.Timespec)
	}
	if ctx.ScMeta.Name == "futex_waitv" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, timespecSize), format.Timespec)
	}
	if ctx.ScMeta.Name == "clock_gettime" || ctx.ScMeta.Name == "clock_getres" {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, timespecSize), format.Timespec)
	}
	if ctx.ScMeta.Name == "clock_settime" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, timespecSize), format.Timespec)
	}

	isNanosleep := ctx.ScMeta.Name == "nanosleep"
	isClockNanosleep := ctx.ScMeta.Name == "clock_nanosleep"
	if isNanosleep || isClockNanosleep {
		isOutParam := (isNanosleep && i == 1) || (isClockNanosleep && i == 3)
		if isOutParam {
			if ctx.Ret != -516 && ctx.Ret != -4 {
				return "", false
			}
			return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, timespecSize), format.Timespec)
		}
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, timespecSize), format.Timespec)
	}

	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, timespecSize), format.Timespec)
}

func decodeTimeval(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "utimes" || ctx.ScMeta.Name == "futimesat" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, 32), format.Timevals)
	}

	isOut := ctx.ScMeta.Name == "gettimeofday"
	if isOut {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, timespecSize), format.Timeval)
	}
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, timespecSize), format.Timeval)
}

func decodeUtimbuf(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, timespecSize), format.Utimbuf)
}

func decodeTimex(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, timexSize), func(data []byte) string {
		return format.TimexWithCatalog(catalogForContext(ctx), data)
	})
}

type timeSnapshot struct {
	argIndex  int
	size      int
	direction PayloadDirection
}

func enterTimeSnapshot(argIndex int, size int) timeSnapshot {
	return timeSnapshot{argIndex: argIndex, size: size, direction: PayloadDirectionIn}
}

func exitTimeSnapshot(argIndex int, size int) timeSnapshot {
	return timeSnapshot{argIndex: argIndex, size: size, direction: PayloadDirectionOut}
}

func decodeTimeSnapshot(ctx *Context, val uint64, snap timeSnapshot, decodeFn func([]byte) string) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	data, ok := snapshotTimeData(ctx, snap)
	if ok {
		return decodeFn(data), true
	}
	return pointerString(val), true
}

func snapshotTimeData(ctx *Context, snap timeSnapshot) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(snap.argIndex, snap.direction); ok {
		return boundedBpfStructData(data, snap.size)
	}
	return nil, false
}

func pointerString(val uint64) string {
	return formatPointer(val)
}

func decodeItimerval(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := ctx.ScMeta.Name == "getitimer" && i == 1 || ctx.ScMeta.Name == "setitimer" && i == 2
	if isOut {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, 32), format.Itimerval)
	}
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, 32), format.Itimerval)
}

func decodeItimerspec(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := (ctx.ScMeta.Name == "timerfd_gettime" && i == 1) || (ctx.ScMeta.Name == "timerfd_settime" && i == 3) || (ctx.ScMeta.Name == "timer_gettime" && i == 1) || (ctx.ScMeta.Name == "timer_settime" && i == 3)
	if isOut {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, 32), format.Itimerspec)
	}
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, 32), format.Itimerspec)
}

func decodeTimezone(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := ctx.ScMeta.Name == "gettimeofday" && i == 1
	if isOut {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, 8), format.Timezone)
	}
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, 8), format.Timezone)
}
