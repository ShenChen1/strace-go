package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMainUsesErrorReturningBootstrap(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/main.go"))
	for _, forbidden := range []string{"log.Fatal(", "log.Fatalf(", "log.Fatalln("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("main bootstrap still uses %q", forbidden)
		}
	}
	if !strings.Contains(source, "func runMain(args []string) error") {
		t.Fatal("main must delegate bootstrap to an error-returning runner")
	}
	if !strings.Contains(source, "func runTraceSession(config *traceLaunchConfig, clock traceClock) error") {
		t.Fatal("bootstrap resources must be owned by runTraceSession")
	}
	for _, required := range []string{
		"newTraceTargetHandoff(config.targets, targetRuntime, bpfRuntime, targetPid)",
		"targetHandoff.Transfer()",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("bootstrap is missing target ownership step %q", required)
		}
	}
}

func TestTraceTargetPIDsDeduplicatesCommandAndAttachTargets(t *testing.T) {
	got := traceTargetPIDs([]int{202, 303, 202}, 202)
	want := []uint32{202, 303}
	if len(got) != len(want) {
		t.Fatalf("target pids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target pids = %v, want %v", got, want)
		}
	}
}
