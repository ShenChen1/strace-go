package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
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
	if !strings.Contains(source, "func runTraceSession(opts *cli.Options, clock traceClock) error") {
		t.Fatal("bootstrap resources must be owned by runTraceSession")
	}
	if !strings.Contains(source, "abortTraceTargets(opts, cmd, bpfObjs, targetPid)") {
		t.Fatal("bootstrap must clean all trace targets on error")
	}
}

func TestTraceTargetPIDsDeduplicatesCommandAndAttachTargets(t *testing.T) {
	got := traceTargetPIDs(&cli.Options{AttachPids: []int{202, 303, 202}}, 202)
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
