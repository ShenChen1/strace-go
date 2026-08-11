package main

import "golang.org/x/sys/unix"

type fdCreatorState struct {
	path         string
	cloexec      bool
	cloexecKnown bool
}

// fdCreatorPolicy isolates the state contract for syscalls that return a new FD.
// Special creators such as signalfd can later implement different matching logic
// without spreading their creation predicate across every FD state updater.
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

var fdCreatorPolicies = []fdCreatorPolicy{
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
