package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func newJSONSyscallEvent(eventRaw *bpfEvent, scMeta meta.Syscall, sections []handler.PayloadSection) jsonSyscallEvent {
	return newJSONSyscallEventFromView(newSyscallEventViewFromBPF(eventRaw), scMeta, sections)
}
