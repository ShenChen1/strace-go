package main

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestBuildSyscallFilterPlanExplicitTrace(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=write", "/bin/true"})
	plan := newTraceBPFConfig(opts).syscallFilter

	if !plan.enabled {
		t.Fatal("filter plan disabled, want enabled")
	}
	if plan.negated {
		t.Fatal("filter plan negated, want include filter")
	}
	requirePlanHasSyscall(t, plan, "write")
	requirePlanLacksSyscall(t, plan, "read")
}

func TestBuildSyscallFilterPlanRegexTrace(t *testing.T) {
	opts := cli.ParseArgs([]string{"--trace=/^getp", "/bin/true"})
	plan := newTraceBPFConfig(opts).syscallFilter

	if !plan.enabled {
		t.Fatal("filter plan disabled, want enabled")
	}
	requirePlanHasSyscall(t, plan, "getpid")
	requirePlanHasSyscall(t, plan, "getppid")
	requirePlanLacksSyscall(t, plan, "write")
}

func TestBuildSyscallFilterPlanNegatedTrace(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=!write", "/bin/true"})
	plan := newTraceBPFConfig(opts).syscallFilter

	if !plan.enabled {
		t.Fatal("filter plan disabled, want enabled")
	}
	if !plan.negated {
		t.Fatal("filter plan negated = false, want true")
	}
	requirePlanHasSyscall(t, plan, "write")
}

func TestBuildSyscallFilterPlanTraceAllStaysDisabled(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=all", "/bin/true"})
	plan := newTraceBPFConfig(opts).syscallFilter

	if plan.enabled {
		t.Fatal("trace=all produced a BPF filter, want no BPF filter")
	}
}

func requirePlanHasSyscall(t *testing.T, plan syscallFilterPlan, name string) {
	t.Helper()
	id := syscallIDByName(t, name)
	for _, got := range plan.ids {
		if got == id {
			return
		}
	}
	t.Fatalf("filter plan ids %v does not include %s(%d)", plan.ids, name, id)
}

func requirePlanLacksSyscall(t *testing.T, plan syscallFilterPlan, name string) {
	t.Helper()
	id := syscallIDByName(t, name)
	for _, got := range plan.ids {
		if got == id {
			t.Fatalf("filter plan ids %v unexpectedly include %s(%d)", plan.ids, name, id)
		}
	}
}
