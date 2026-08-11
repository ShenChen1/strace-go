package main

import (
	"golang.org/x/sys/unix"
	"strace-go/pkg/format"
	"strace-go/pkg/handler"
)

type fdCreatorState struct {
	path         string
	pathKnown    bool
	cloexec      bool
	cloexecKnown bool
}

// fdCreatorPolicy isolates state for syscalls that create or update an FD.
// Special policies such as signalfd keep their predicate and payload rules out
// of the individual observation, path, and CLOEXEC updaters.
type fdCreatorPolicy interface {
	matches(syscallName string, view syscallEventView) bool
	state(src fdStateSource) fdCreatorState
}

type simpleFDCreatorPolicy struct {
	syscallName  string
	path         string
	flagsArg     int
	fixedCloexec bool
	cloexecKnown bool
}

func (p simpleFDCreatorPolicy) matches(syscallName string, _ syscallEventView) bool {
	return syscallName == p.syscallName
}

func (p simpleFDCreatorPolicy) state(src fdStateSource) fdCreatorState {
	state := fdCreatorState{
		path:         p.path,
		pathKnown:    p.path != "",
		cloexec:      p.fixedCloexec,
		cloexecKnown: p.cloexecKnown,
	}
	if p.flagsArg < 0 {
		return state
	}
	flags := uint64(uint32(src.view.args[p.flagsArg]))
	state.cloexec = flags&uint64(unix.O_CLOEXEC) != 0
	state.cloexecKnown = true
	return state
}

type signalfdPolicy struct {
	syscallName string
	flagsArg    int
}

func (p signalfdPolicy) matches(syscallName string, _ syscallEventView) bool {
	return syscallName == p.syscallName
}

func (p signalfdPolicy) state(src fdStateSource) fdCreatorState {
	state := fdCreatorState{}
	if int32(src.view.args[0]) == -1 {
		state.cloexecKnown = true
	}
	if state.cloexecKnown && p.flagsArg >= 0 {
		flags := uint64(uint32(src.view.args[p.flagsArg]))
		state.cloexec = flags&uint64(unix.O_CLOEXEC) != 0
	}
	mask, ok := signalfdMaskFromSource(src)
	if !ok {
		return state
	}
	state.path = "signalfd:" + format.Sigset(mask)
	state.pathKnown = true
	return state
}

func signalfdMaskFromSource(src fdStateSource) ([]byte, bool) {
	if src.view.args[2] != 8 {
		return nil, false
	}
	for _, section := range src.payloadSections {
		if section.Kind != handler.PayloadKindStruct ||
			section.Direction != handler.PayloadDirectionIn ||
			section.ArgIndex != 1 || section.UserLen != 8 ||
			section.CopiedLen < 8 || section.ProbeRet != 0 || len(section.Data) < 8 {
			continue
		}
		return section.Data[:8], true
	}
	return nil, false
}

var fdCreatorPolicies = []fdCreatorPolicy{
	signalfdPolicy{syscallName: "signalfd", flagsArg: -1},
	signalfdPolicy{syscallName: "signalfd4", flagsArg: 3},
	simpleFDCreatorPolicy{
		syscallName:  "eventfd",
		path:         "anon_inode:[eventfd]",
		flagsArg:     -1,
		cloexecKnown: true,
	},
	simpleFDCreatorPolicy{
		syscallName: "eventfd2",
		path:        "anon_inode:[eventfd]",
		flagsArg:    1,
	},
	simpleFDCreatorPolicy{
		syscallName:  "epoll_create",
		path:         "anon_inode:[eventpoll]",
		flagsArg:     -1,
		cloexecKnown: true,
	},
	simpleFDCreatorPolicy{
		syscallName: "epoll_create1",
		path:        "anon_inode:[eventpoll]",
		flagsArg:    0,
	},
	simpleFDCreatorPolicy{
		syscallName: "timerfd_create",
		path:        "anon_inode:[timerfd]",
		flagsArg:    1,
	},
	simpleFDCreatorPolicy{
		syscallName:  "inotify_init",
		path:         "anon_inode:inotify",
		flagsArg:     -1,
		cloexecKnown: true,
	},
	simpleFDCreatorPolicy{
		syscallName: "inotify_init1",
		path:        "anon_inode:inotify",
		flagsArg:    0,
	},
}

func fdCreatorPolicyFor(syscallName string, view syscallEventView) (fdCreatorPolicy, bool) {
	for _, policy := range fdCreatorPolicies {
		if policy.matches(syscallName, view) {
			return policy, true
		}
	}
	return nil, false
}

func isFDStateCreatorForView(syscallName string, view syscallEventView) bool {
	_, ok := fdCreatorPolicyFor(syscallName, view)
	return ok
}
