package main

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceScopeAllowsTargetWithoutAttach(t *testing.T) {
	scope := newTraceScope(101, &cli.Options{})

	if !scope.Allows(&bpfEvent{Pid: 101}) {
		t.Fatal("target pid should be allowed")
	}
	if scope.Allows(&bpfEvent{Pid: 202}) {
		t.Fatal("unrelated pid should be rejected without follow-forks")
	}
}

func TestTraceScopeUsesAttachPidsAsDirectMatches(t *testing.T) {
	scope := newTraceScope(101, &cli.Options{AttachPids: []int{202}})

	if !scope.Allows(&bpfEvent{Pid: 202}) {
		t.Fatal("attached pid should be allowed")
	}
	if scope.Allows(&bpfEvent{Pid: 101}) {
		t.Fatal("target pid should not be a direct match when attach pids are configured")
	}
}

func TestTraceScopeAllowsForksWhenEnabled(t *testing.T) {
	scope := newTraceScope(101, &cli.Options{AttachPids: []int{202}, FollowForks: true})

	if !scope.Allows(&bpfEvent{Pid: 303}) {
		t.Fatal("follow-forks should allow non-direct pids")
	}
}
