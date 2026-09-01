package main

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceFDSpecialSetsRemainConfigured(t *testing.T) {
	all := newTraceFilterOptions(cli.ParseArgs([]string{"--trace-fds=all", "/bin/true"}))
	if !all.HasFDFilter() || !all.MatchFDs([]int32{3}) || all.MatchFDs([]int32{-1}) {
		t.Fatal("trace-fds=all did not match every valid descriptor")
	}

	none := newTraceFilterOptions(cli.ParseArgs([]string{"--trace-fds=none", "/bin/true"}))
	if !none.HasFDFilter() || none.MatchFDs([]int32{3}) || none.IsUnfiltered() {
		t.Fatal("trace-fds=none was not preserved as an explicit empty filter")
	}
}
