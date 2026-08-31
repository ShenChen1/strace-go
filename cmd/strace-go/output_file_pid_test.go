package main

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestFollowForksOutputFileAlwaysPrefixesNumericPID(t *testing.T) {
	policy := newTraceOutputPolicy(cli.ParseArgs([]string{
		"-f", "-o", "trace.log", "/bin/true",
	}))
	options := policy.RenderOptions()
	if !options.showPID || !options.alwaysShowPID {
		t.Fatalf("file render options = %+v, want numeric PID on every line", options)
	}

	separate := newTraceOutputPolicy(cli.ParseArgs([]string{
		"-ff", "-o", "trace.log", "/bin/true",
	})).RenderOptions()
	if separate.showPID || separate.alwaysShowPID {
		t.Fatalf("separate file render options = %+v, want no PID prefix", separate)
	}
}
