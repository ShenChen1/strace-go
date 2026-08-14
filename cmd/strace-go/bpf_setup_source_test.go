package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFSetupHasExplicitStageBoundaries(t *testing.T) {
	root := repoRootForTest(t)
	runtimeSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_runtime.go"))
	setupSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_setup.go"))
	for _, required := range []string{
		"func setupBPFWithClock(clock traceClock)",
		"measureBPFSetupStage(",
		"bpfSetupSpecStage",
		"bpfSetupObjectsStage",
		"bpfSetupRouteMapsStage",
		"bpfSetupTracepointsStage",
	} {
		if !strings.Contains(setupSource, required) {
			t.Fatalf("BPF setup is missing stage boundary %q", required)
		}
	}
	if strings.Contains(runtimeSource, "func setupBPF()") {
		t.Fatal("bpf_runtime.go still owns setup orchestration")
	}
}

func TestBPFAttacherSeparatesRequiredAndOptionalAttachment(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/bpf_attach.go"))
	for _, required := range []string{
		"func (a *bpfAttacher) attachRequired()",
		"func (a *bpfAttacher) attachOptionalRecvmsg()",
		"attachRequired()",
		"attachOptionalRecvmsg()",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("BPF attachment boundary is missing %q", required)
		}
	}
}
