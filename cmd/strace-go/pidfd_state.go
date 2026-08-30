package main

import "fmt"

type pidfdCreatorPolicy struct{}

func (pidfdCreatorPolicy) matches(syscallName string, _ syscallEventView) bool {
	return syscallName == "pidfd_open"
}

func (pidfdCreatorPolicy) state(src fdStateSource) fdCreatorState {
	pid := int32(uint32(src.view.args[0]))
	state := fdCreatorState{
		cloexec:      true,
		cloexecKnown: true,
	}
	if pid <= 0 {
		return state
	}
	state.path = fmt.Sprintf("anon_inode:[pidfd],pid=%d", pid)
	state.pathKnown = true
	return state
}
