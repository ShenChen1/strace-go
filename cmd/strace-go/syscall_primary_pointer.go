package main

import (
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func primarySyscallPointer(scMeta meta.Syscall, args [6]uint64, sections []handler.PayloadSection) uint64 {
	if ptr := primaryInputStringPayloadPointer(sections); ptr != 0 {
		return ptr
	}
	if index, ok := primaryPathArgIndex(scMeta); ok {
		return args[index]
	}
	return 0
}

func primaryInputStringPayloadPointer(sections []handler.PayloadSection) uint64 {
	for _, section := range sections {
		if section.Kind == handler.PayloadKindString &&
			section.Direction == handler.PayloadDirectionIn &&
			section.UserPtr != 0 {
			return section.UserPtr
		}
	}
	return 0
}

func primaryPathArgIndex(scMeta meta.Syscall) (int, bool) {
	for index, name := range scMeta.Args {
		if index >= 6 {
			return 0, false
		}
		if isPrimaryPathArgName(name) {
			return index, true
		}
	}
	return 0, false
}

func isPrimaryPathArgName(name string) bool {
	switch name {
	case "filename", "pathname", "path", "oldname", "newname", "oldpath", "newpath", "fs_name":
		return true
	default:
		return false
	}
}
