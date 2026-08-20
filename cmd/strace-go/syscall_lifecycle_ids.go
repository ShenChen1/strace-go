package main

import "strace-go/pkg/meta"

type syscallLifecycleIDs struct {
	exit         uint32
	exitGroup    uint32
	hasExit      bool
	hasExitGroup bool
}

func newSyscallLifecycleIDs(table map[uint32]meta.Syscall) syscallLifecycleIDs {
	var ids syscallLifecycleIDs
	for id, scMeta := range table {
		switch scMeta.Name {
		case "exit":
			ids.exit = id
			ids.hasExit = true
		case "exit_group":
			ids.exitGroup = id
			ids.hasExitGroup = true
		}
	}
	return ids
}

func (ids syscallLifecycleIDs) configured() bool {
	return ids.hasExit || ids.hasExitGroup
}

func (ids syscallLifecycleIDs) isTerminating(sysID uint32) bool {
	return (ids.hasExit && sysID == ids.exit) ||
		(ids.hasExitGroup && sysID == ids.exitGroup)
}
