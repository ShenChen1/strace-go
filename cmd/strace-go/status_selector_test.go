package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestStatusComplementUnavailableKeepsCompletedAndUnfinishedEvents(t *testing.T) {
	policy := newTraceOutputPolicy(cli.ParseArgs([]string{
		"--status=!unavailable", "/bin/true",
	}))
	completed := syscallEventContext{
		view:        syscallEventView{valid: true, ret: 1},
		meta:        meta.Syscall{Name: "getpid"},
		shouldPrint: true,
	}
	if !policy.ShouldEmit(completed, false) {
		t.Fatal("status=!unavailable rejected a successful completed event")
	}
	if !policy.ShouldEmit(completed, true) {
		t.Fatal("status=!unavailable rejected an unfinished event")
	}

	unavailable := completed
	unavailable.view.probeRetEnter = 3
	if policy.ShouldEmit(unavailable, false) {
		t.Fatal("status=!unavailable accepted an unavailable event")
	}
}
