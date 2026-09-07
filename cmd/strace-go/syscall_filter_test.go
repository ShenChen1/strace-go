package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
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

func TestBuildSyscallFilterPlanTraceNoneRejectsAll(t *testing.T) {
	opts := cli.ParseArgs([]string{"-e", "trace=none", "/bin/true"})
	plan := newTraceBPFConfig(opts).syscallFilter

	if !plan.enabled || plan.negated || len(plan.ids) != 0 {
		t.Fatalf("trace=none plan = %+v, want enabled empty include filter", plan)
	}
}

func TestBuildSyscallFilterPlanQualifiedTraceRejectsUnknownIDs(t *testing.T) {
	opts := cli.ParseArgs([]string{"--trace=getpid@64", "/bin/true"})
	plan := newTraceBPFConfig(opts).syscallFilter
	if !plan.strictUnknown {
		t.Fatal("qualified trace selector did not enable strict unknown filtering")
	}
}

func TestMaterializeSyscallFilterEntriesDistinguishesUnknownIDs(t *testing.T) {
	plan := syscallFilterPlan{enabled: true, ids: []uint32{9}}
	table := map[uint32]meta.Syscall{
		1: {Name: "read"},
		9: {Name: "write"},
	}

	entries := materializeSyscallFilterEntries(plan, table)
	want := []syscallFilterEntry{
		{id: 1, selected: 0},
		{id: 9, selected: 1},
	}
	if len(entries) != len(want) {
		t.Fatalf("filter entries = %+v, want %+v", entries, want)
	}
	for index := range want {
		if entries[index] != want[index] {
			t.Fatalf("filter entry %d = %+v, want %+v", index, entries[index], want[index])
		}
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
