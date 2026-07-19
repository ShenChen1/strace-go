package main

import (
	"fmt"
	"strings"
	"syscall"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

// IMPACT: formatSyscallRet formats raw returns including negative error values or hex numbers for custom functions.
func formatSyscallRet(scName string, ret int64, res handler.Result, ctx *handler.Context) string {
	if scName == "exit" || scName == "exit_group" {
		return "?"
	}
	retStr := fmt.Sprintf("%d", ret)
	if ret >= 0 && ctx != nil && ctx.Opts != nil && ctx.Opts.ShowPaths && isFdReturnSyscall(scName) {
		retStr = handler.FormatFdWithPath(ctx, int32(ret))
	}
	if ret > 0 && (scName == "fcntl" || scName == "fcntl64") && ctx != nil {
		cmdVal := uint32(ctx.Args[1])
		switch cmdVal {
		case 1, 3, 1025: // F_GETFD (1), F_GETFL (3), F_GETLEASE (1025)
			retStr = fmt.Sprintf("%#x", ret)
		}
	}
	if ret >= 0 && scName == "umask" {
		m := uint32(ret)
		s := fmt.Sprintf("%o", m)
		if len(s) < 3 {
			s = strings.Repeat("0", 3-len(s)) + s
		}
		if s[0] != '0' {
			s = "0" + s
		}
		retStr = s
	}
	if ret >= 0 && (scName == "brk" || scName == "mmap" || scName == "mremap") {
		retStr = fmt.Sprintf("%#x", ret)
	}
	if ret >= 0 && (scName == "adjtimex" || scName == "clock_adjtime") {
		retStr = fmt.Sprintf("%d (%s)", ret, timeStateName(ret))
	}
	if ret < 0 && ret >= -4095 {
		retStr = formatErrnoReturn(int(-ret))
	}
	if res.ReturnDesc != "" || res.ShowEmptyReturnDesc {
		retStr += " (" + res.ReturnDesc + ")"
	}
	return retStr
}

func timeStateName(ret int64) string {
	switch ret {
	case 1:
		return "TIME_INS"
	case 2:
		return "TIME_DEL"
	case 3:
		return "TIME_OOP"
	case 4:
		return "TIME_WAIT"
	case 5:
		return "TIME_ERROR"
	default:
		return "TIME_OK"
	}
}

func formatErrnoReturn(errNum int) string {
	switch errNum {
	case 516:
		return "? ERESTART_RESTARTBLOCK (Interrupted by signal)"
	case 514:
		return "? ERESTARTNOHAND (To be restarted if no handler)"
	case 513:
		return "? ERESTARTNOINTR (To be restarted)"
	case 512:
		return "? ERESTARTSYS (To be restarted if SA_RESTART is set)"
	}
	errDesc := syscall.Errno(errNum).Error()
	if len(errDesc) > 0 {
		errDesc = strings.ToUpper(errDesc[:1]) + errDesc[1:]
	}
	if errName, ok := meta.ErrnoTable[errNum]; ok {
		return fmt.Sprintf("-1 %s (%s)", errName, errDesc)
	}
	return fmt.Sprintf("-1 E%d (%s)", errNum, errDesc)
}
