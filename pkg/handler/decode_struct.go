package handler

import (
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

// decodeStruct decodes structured pointer arguments.
func (h *DefaultHandler) decodeStruct(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "utimensat" && strings.Contains(argTyp, "struct timespec *") {
		data := ctx.StrArgBuf[512 : 512+32]
		readSuccess := ctx.IsArgReadSuccess(2)
		var err error
		if !readSuccess || ctx.ProbeRetEnter < 0 {
			data, err = ctx.MemReader.ReadRobust(ctx.Pid, val, 32, false)
			readSuccess = (err == nil && len(data) == 32)
		}
		if !readSuccess {
			return fmt.Sprintf("%#x", val), true
		}
		return format.Utimes(data), true
	}

	if strings.Contains(argTyp, "struct timespec *") || strings.Contains(argTyp, "struct __kernel_timespec *") {
		isNanosleep := ctx.ScMeta.Name == "nanosleep"
		isClockNanosleep := ctx.ScMeta.Name == "clock_nanosleep"
		if isNanosleep || isClockNanosleep {
			isOutParam := (isNanosleep && i == 1) || (isClockNanosleep && i == 3)
			if isOutParam {
				if ctx.Ret != -516 && ctx.Ret != -4 {
					return "", false
				}
				data := ctx.StrArgBuf[1024 : 1024+16]
				readSuccess := ctx.ProbeRetExit >= 0
				if !readSuccess {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false); err == nil && len(d) == 16 {
						data = d
					}
				}
				return format.Timespec(data), true
			} else {
				data := ctx.StrArgBuf[0:16]
				readSuccess := ctx.ProbeRetEnter >= 0
				if !readSuccess {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false); err == nil && len(d) == 16 {
						data = d
					}
				}
				return format.Timespec(data), true
			}
		}

		off := 0
		data := ctx.StrArgBuf[off : off+16]
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false); err == nil && len(d) == 16 {
				data = d
			}
		}
		return format.Timespec(data), true
	}

	if strings.Contains(argTyp, "struct timeval *") {
		data := ctx.StrArgBuf[1024 : 1024+16]
		if ctx.Ret >= 0 || ctx.ProbeRetExit >= 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 16, false); err == nil && len(d) == 16 {
				data = d
			}
		}
		return format.Timeval(data), true
	}

	if strings.Contains(argTyp, "struct timex *") || strings.Contains(argTyp, "struct __kernel_timex *") {
		data := ctx.StrArgBuf[1024 : 1024+208]
		if ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 208, true); err == nil && len(d) == 208 {
				data = d
			}
		}
		return format.Timex(data), true
	}

	if strings.Contains(argTyp, "struct stat *") || strings.Contains(argTyp, "struct stat64 *") || strings.Contains(argTyp, "struct new_stat *") || strings.Contains(argTyp, "struct __old_kernel_stat *") {
		if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
			return fmt.Sprintf("%#x", val), true
		}
		data := ctx.StrArgBuf[1024 : 1024+144]
		if ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 144, true); err == nil && len(d) == 144 {
				data = d
			}
		}
		return format.Stat(data), true
	}

	if strings.Contains(argTyp, "struct sysinfo *") {
		if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
			return fmt.Sprintf("%#x", val), true
		}
		data := ctx.StrArgBuf[1024 : 1024+112]
		if ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 112, true); err == nil && len(d) == 112 {
				data = d
			}
		}
		return format.Sysinfo(data), true
	}

	if strings.Contains(argTyp, "struct statfs *") || strings.Contains(argTyp, "struct statfs64 *") {
		if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
			return fmt.Sprintf("%#x", val), true
		}
		data := ctx.StrArgBuf[1024 : 1024+120]
		if ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 120, true); err == nil && len(d) == 120 {
				data = d
			}
		}
		return format.Statfs(data), true
	}

	if strings.Contains(argTyp, "struct flock *") || strings.Contains(argTyp, "struct flock64 *") {
		if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
			return fmt.Sprintf("%#x", val), true
		}
		data := ctx.StrArgBuf[0:32]
		readSuccess := ctx.ProbeRetEnter >= 0
		if ctx.ProbeRetExit >= 0 {
			data = ctx.StrArgBuf[1024 : 1024+32]
			readSuccess = true
		}
		if !readSuccess {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 32, false); err == nil && len(d) == 32 {
				data = d
				readSuccess = true
			}
		}
		if !readSuccess {
			return fmt.Sprintf("%#x", val), true
		}
		cmd := uint32(ctx.Args[1])
		cmdStr := meta.DecodeFlags(uint64(cmd), "fcntl_cmds")
		showsPid := strings.Contains(cmdStr, "GETLK")
		return format.Flock(data, showsPid), true
	}

	if strings.Contains(argTyp, "struct f_owner_ex *") {
		if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
			return fmt.Sprintf("%#x", val), true
		}
		data := ctx.StrArgBuf[0:8]
		readSuccess := ctx.ProbeRetEnter >= 0
		if ctx.ProbeRetExit >= 0 {
			data = ctx.StrArgBuf[1024 : 1024+8]
			readSuccess = true
		}
		if !readSuccess {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 8, false); err == nil && len(d) == 8 {
				data = d
				readSuccess = true
			}
		}
		if !readSuccess {
			return fmt.Sprintf("%#x", val), true
		}
		return format.FOwnerEx(data), true
	}

	return "", false
}
