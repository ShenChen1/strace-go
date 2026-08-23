package main

import "strace-go/pkg/meta"

type syscallEventTraits uint8

const (
	syscallEventTraitHandler syscallEventTraits = 1 << iota
	syscallEventTraitState
	syscallEventTraitStateRead
	syscallEventTraitOffset
	syscallEventTraitOffsetIO
	syscallEventTraitCreator
	syscallEventTraitClose
	syscallEventTraitExit
)

const syscallEventTraitTableSize = 512

var syscallEventTraitsByID = buildSyscallEventTraits()

func buildSyscallEventTraits() [syscallEventTraitTableSize]syscallEventTraits {
	var table [syscallEventTraitTableSize]syscallEventTraits
	for id, scMeta := range meta.SyscallTable {
		if id >= uint32(len(table)) {
			continue
		}
		table[id] = syscallEventTraitsForName(scMeta.Name)
	}
	return table
}

func syscallEventTraitsForName(name string) syscallEventTraits {
	var traits syscallEventTraits
	if isFDStateCreatorName(name) {
		traits |= syscallEventTraitHandler | syscallEventTraitState |
			syscallEventTraitOffset | syscallEventTraitCreator
	}

	switch name {
	case "open", "openat", "openat2", "open_tree", "creat",
		"dup", "dup2", "dup3", "close", "close_range", "pipe", "pipe2",
		"socketpair", "fcntl", "fcntl64", "faccessat", "faccessat2",
		"chmodat", "mkdirat", "newfstatat", "fstat", "chdir", "fchdir":
		traits |= syscallEventTraitHandler
	}

	switch name {
	case "open", "openat", "openat2", "open_tree", "creat",
		"dup", "dup2", "dup3", "fcntl", "fcntl64", "socket", "chdir",
		"fchdir", "close_range":
		traits |= syscallEventTraitState
	case "read":
		traits |= syscallEventTraitStateRead
	}

	switch name {
	case "open", "openat", "openat2", "open_tree", "creat",
		"dup", "dup2", "dup3", "fcntl", "fcntl64", "lseek":
		traits |= syscallEventTraitOffset
	case "read", "write":
		traits |= syscallEventTraitOffsetIO
	}

	if name == "close" {
		traits |= syscallEventTraitClose
	}
	if name == "exit" || name == "exit_group" {
		traits |= syscallEventTraitExit
	}
	return traits
}

func syscallEventTraitsForView(view syscallEventView, syscallName string) syscallEventTraits {
	if view.sysID == 0 {
		if syscallName == "read" {
			return syscallEventTraitsByID[0]
		}
		return syscallEventTraitsForName(syscallName)
	}
	if view.sysID < uint32(len(syscallEventTraitsByID)) {
		return syscallEventTraitsByID[view.sysID]
	}
	return syscallEventTraitsForName(syscallName)
}

func (ev syscallEventContext) eventTraits() syscallEventTraits {
	if ev.traitsBound {
		return ev.traits
	}
	if ev.view.sysID > 0 && ev.view.sysID < uint32(len(syscallEventTraitsByID)) {
		return syscallEventTraitsByID[ev.view.sysID]
	}
	name := ev.meta.Name
	if name == "" {
		name = ev.syscallName()
	}
	return syscallEventTraitsForView(ev.view, name)
}
