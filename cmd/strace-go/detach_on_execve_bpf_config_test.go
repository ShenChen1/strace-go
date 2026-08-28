package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestDetachOnExecveForcesExecCaptureIntoPositiveBPFFilter(t *testing.T) {
	opts := cli.ParseArgs([]string{"-b", "execve", "-e", "trace=read", "/bin/true"})
	plan := newTraceBPFConfig(opts).syscallFilter

	for _, name := range []string{"read", "execve", "execveat"} {
		if !syscallFilterPlanIncludes(plan, name) {
			t.Fatalf("BPF filter excludes %s required by detach-on-exec", name)
		}
	}
	if syscallFilterPlanIncludes(plan, "write") {
		t.Fatal("BPF filter includes unrelated write syscall")
	}
}

func TestDetachOnExecveRemovesExecFromNegatedBPFFilter(t *testing.T) {
	opts := cli.ParseArgs([]string{"-b", "execve", "-e", "trace=!execve,execveat", "/bin/true"})
	plan := newTraceBPFConfig(opts).syscallFilter

	for _, name := range []string{"execve", "execveat", "read"} {
		if !syscallFilterPlanIncludes(plan, name) {
			t.Fatalf("negated BPF filter excludes %s required by detach-on-exec", name)
		}
	}
}

func syscallFilterPlanIncludes(plan syscallFilterPlan, name string) bool {
	if !plan.enabled {
		return true
	}
	listed := false
	for id, syscall := range meta.SyscallTable {
		if syscall.Name != name {
			continue
		}
		for _, plannedID := range plan.ids {
			if plannedID == id {
				listed = true
				break
			}
		}
	}
	return listed != plan.negated
}
