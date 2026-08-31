package main

import (
	"strconv"

	"strace-go/pkg/handler"
)

func (r *TextRenderer) writePlainUnfinishedFast(ev syscallEventContext, res handler.Result) bool {
	if r == nil || r.out == nil || len(res.ArgParts) != 0 || ev.syscallName() == "nanosleep" {
		return false
	}
	options := r.renderOptions()
	if !fastTextPrefixAllowed(options) {
		return false
	}
	name := ev.syscallName()
	if name == "" {
		return false
	}
	buffer, _ := r.startFastTextLine(ev.eventView(), options)
	buffer = append(buffer, name...)
	buffer = append(buffer, "( <unfinished ...>"...)
	buffer = append(buffer, '\n')
	r.writeFastTextBuffer(buffer)
	return true
}

func (r *TextRenderer) writePlainSyscallFast(ev syscallEventContext, res handler.Result) bool {
	if r == nil || r.out == nil || len(res.ArgParts) != 0 || res.HexDumpStr != "" ||
		res.ReturnDesc != "" || res.ShowEmptyReturnDesc {
		return false
	}
	view := ev.eventView()
	if view.ret < 0 {
		return false
	}
	options := r.renderOptions()
	if !fastTextPrefixAllowed(options) || !fastTextReturnAllowed(ev, options) {
		return false
	}
	name := ev.syscallName()
	if name == "" || name == "exit" || name == "exit_group" ||
		name == "nanosleep" || name == "clock_nanosleep" {
		return false
	}
	resumed := ev.pendingEnter != nil && ev.pendingEnter.unfinishedPrinted
	if !resumed {
		resumed = r.consumeSuspended(int(view.tid))
	}
	lineLen := len(name) + 2
	buffer, prefixLen := r.startFastTextLine(view, options)
	if resumed {
		buffer = append(buffer, "<... "...)
		buffer = append(buffer, name...)
		buffer = append(buffer, " resumed>)"...)
		lineLen = len(name) + len("<...  resumed>)")
	} else {
		buffer = append(buffer, name...)
		buffer = append(buffer, "()"...)
	}
	buffer = appendFastTextPadding(buffer, prefixLen, lineLen, options.alignCol)
	buffer = append(buffer, "= "...)
	buffer = strconv.AppendInt(buffer, view.ret, 10)
	buffer = append(buffer, '\n')
	r.writeFastTextBuffer(buffer)
	return true
}

func fastTextPrefixAllowed(options traceRenderOptions) bool {
	return options.printSyscallTime == false && options.stackTrace == false &&
		options.instructionPointer == false &&
		options.time.printTimeMode == 0 && !options.time.printRelativeTime &&
		!options.decodePIDsComm && !options.decodePIDsPIDNS
}

func fastTextReturnAllowed(ev syscallEventContext, options traceRenderOptions) bool {
	if ev.handlerContext != nil && ev.handlerContext.Opts != nil && ev.handlerContext.Opts.ShowPathsValue() {
		return false
	}
	if options.showPID && ev.view.tid == 0 {
		return false
	}
	switch ev.syscallName() {
	case "fcntl", "fcntl64", "umask", "brk", "mmap", "mremap", "adjtimex", "clock_adjtime":
		return false
	default:
		return true
	}
}

func (r *TextRenderer) startFastTextLine(view syscallEventView, options traceRenderOptions) ([]byte, int) {
	buffer := r.lineBuffer[:0]
	timePrefix := r.timePrefix(view.enterTime)
	buffer = append(buffer, timePrefix...)
	if options.showPID {
		start := len(buffer)
		buffer = strconv.AppendInt(buffer, int64(view.tid), 10)
		for len(buffer)-start < 5 {
			buffer = append(buffer, ' ')
		}
		buffer = append(buffer, ' ')
	}
	if options.printSyscallNumber {
		buffer = append(buffer, '[')
		var scratch [20]byte
		number := strconv.AppendUint(scratch[:0], uint64(view.sysID), 10)
		for padding := 4 - len(number); padding > 0; padding-- {
			buffer = append(buffer, ' ')
		}
		buffer = append(buffer, number...)
		buffer = append(buffer, ']', ' ')
	}
	return buffer, len(buffer)
}

func appendFastTextPadding(buffer []byte, prefixLen, lineLen, alignCol int) []byte {
	padding := alignCol - prefixLen - lineLen
	if padding < 1 {
		padding = 1
	}
	for i := 0; i < padding; i++ {
		buffer = append(buffer, ' ')
	}
	return buffer
}

func (r *TextRenderer) writeFastTextBuffer(buffer []byte) {
	_, _ = r.out.Write(buffer)
	r.lineBuffer = buffer
}
