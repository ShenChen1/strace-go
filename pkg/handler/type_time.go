package handler

import (
	"strace-go/pkg/format"
)

func init() {
	RegisterStructDecoder("struct timespec *", StructDecoderFunc(decodeTimespec))
	RegisterStructDecoder("struct __kernel_timespec *", StructDecoderFunc(decodeTimespec))
	RegisterStructDecoder("struct timeval *", StructDecoderFunc(decodeTimeval))
	RegisterStructDecoder("struct utimbuf *", StructDecoderFunc(decodeUtimbuf))
	RegisterStructDecoder("struct timex *", StructDecoderFunc(decodeTimex))
	RegisterStructDecoder("struct __kernel_timex *", StructDecoderFunc(decodeTimex))
	RegisterStructDecoder("struct itimerval *", StructDecoderFunc(decodeItimerval))
	RegisterStructDecoder("struct itimerspec *", StructDecoderFunc(decodeItimerspec))
	RegisterStructDecoder("struct timezone *", StructDecoderFunc(decodeTimezone))
}

func decodeTimespec(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "utimensat" {
		xlatFormat := "abbrev"
		if ctx.Opts != nil {
			xlatFormat = ctx.Opts.XlatFormat
		}
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfMiscArgOffset, 32), func(data []byte) string {
			return format.UtimesWithXlat(data, xlatFormat)
		})
	}
	if ctx.ScMeta.Name == "futex_wait" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfEnterArgOffset, timespecSize), format.Timespec)
	}
	if ctx.ScMeta.Name == "futex_waitv" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, futexWaitvTimeoutOffset, timespecSize), format.Timespec)
	}
	if ctx.ScMeta.Name == "clock_gettime" || ctx.ScMeta.Name == "clock_getres" {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, BpfExitArgOffset, timespecSize), format.Timespec)
	}
	if ctx.ScMeta.Name == "clock_settime" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfEnterArgOffset, timespecSize), format.Timespec)
	}

	isNanosleep := ctx.ScMeta.Name == "nanosleep"
	isClockNanosleep := ctx.ScMeta.Name == "clock_nanosleep"
	if isNanosleep || isClockNanosleep {
		isOutParam := (isNanosleep && i == 1) || (isClockNanosleep && i == 3)
		if isOutParam {
			if ctx.Ret != -516 && ctx.Ret != -4 {
				return "", false
			}
			return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, BpfExitArgOffset, timespecSize), format.Timespec)
		}
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfEnterArgOffset, timespecSize), format.Timespec)
	}

	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfEnterArgOffset, timespecSize), format.Timespec)
}

func decodeTimeval(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "utimes" || ctx.ScMeta.Name == "futimesat" {
		return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfMiscArgOffset, 32), format.Timevals)
	}

	isOut := ctx.ScMeta.Name == "gettimeofday"
	if isOut {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, BpfExitArgOffset, timespecSize), format.Timeval)
	}
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfEnterArgOffset, timespecSize), format.Timeval)
}

func decodeUtimbuf(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfMiscArgOffset, timespecSize), format.Utimbuf)
}

func decodeTimex(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, BpfExitArgOffset, timexSize), format.Timex)
}

type timeSnapshot struct {
	argIndex  int
	offset    int
	size      int
	direction PayloadDirection
}

func enterTimeSnapshot(argIndex int, offset int, size int) timeSnapshot {
	return timeSnapshot{argIndex: argIndex, offset: offset, size: size, direction: PayloadDirectionIn}
}

func exitTimeSnapshot(argIndex int, offset int, size int) timeSnapshot {
	return timeSnapshot{argIndex: argIndex, offset: offset, size: size, direction: PayloadDirectionOut}
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
	if snap.direction == PayloadDirectionOut {
		return ctx.ExitSnapshot(snap.offset, snap.size)
	}
	return ctx.EnterArgSnapshot(snap.argIndex, snap.offset, snap.size)
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
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, BpfExitArgOffset, 32), format.Itimerval)
	}
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfEnterArgOffset, 32), format.Itimerval)
}

func decodeItimerspec(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := (ctx.ScMeta.Name == "timerfd_gettime" && i == 1) || (ctx.ScMeta.Name == "timerfd_settime" && i == 3) || (ctx.ScMeta.Name == "timer_gettime" && i == 1) || (ctx.ScMeta.Name == "timer_settime" && i == 3)
	if isOut {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, BpfExitArgOffset, 32), format.Itimerspec)
	}
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, BpfEnterArgOffset, 32), format.Itimerspec)
}

func decodeTimezone(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	isOut := ctx.ScMeta.Name == "gettimeofday" && i == 1
	if isOut {
		if ctx.Ret < 0 && ctx.Ret >= -4095 {
			return "", false
		}
		return decodeTimeSnapshot(ctx, val, exitTimeSnapshot(i, BpfExitArgOffset+16, 8), format.Timezone)
	}
	offset := BpfEnterArgOffset
	if ctx.ScMeta.Name == "settimeofday" && i == 1 {
		offset = 16
	}
	return decodeTimeSnapshot(ctx, val, enterTimeSnapshot(i, offset, 8), format.Timezone)
}
