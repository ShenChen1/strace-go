package main

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestUnknownSyscallBypassesNameSelectors(t *testing.T) {
	for _, selector := range []string{"none", "read", "!all"} {
		opts := cli.ParseArgs([]string{"--trace=" + selector, "/bin/true"})
		filter := newTraceFilterOptions(opts)
		if !filter.MatchSyscall(unknownSyscallName(472)) {
			t.Fatalf("trace=%s filtered an unknown syscall", selector)
		}
	}
}
