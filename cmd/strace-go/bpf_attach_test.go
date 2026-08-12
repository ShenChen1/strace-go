package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/meta"
)

func TestSetSyscallVariablesDoesNotUseNumericFallback(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/bpf_runtime.go"))
	for _, forbidden := range []string{
		"fallback uint32",
		"sc.fallback",
		`{"SYS_RT_SIGRETURN_COMPAT"`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("setSyscallVariables still contains numeric fallback %q", forbidden)
		}
	}
}

func TestSetSyscallVariablesRejectsMissingGeneratedID(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf() failed: %v", err)
	}

	var syscallID uint32
	var syscallMeta meta.Syscall
	for id, candidate := range meta.SyscallTable {
		if candidate.Name == "capget" {
			syscallID = id
			syscallMeta = candidate
			break
		}
	}
	if syscallMeta.Name == "" {
		t.Fatal("generated syscall table has no capget entry")
	}
	delete(meta.SyscallTable, syscallID)
	defer func() { meta.SyscallTable[syscallID] = syscallMeta }()

	err = setSyscallVariables(spec)
	if err == nil || !strings.Contains(err.Error(), `syscall "capget" is missing`) {
		t.Fatalf("setSyscallVariables() error = %v, want missing capget error", err)
	}
}

func TestRawSyscallTracepointSpecsAreRequired(t *testing.T) {
	specs := rawSyscallTracepointSpecs(&bpfObjects{})
	wantPairs := map[string]bool{
		"sys_enter:trace_sys_enter": true,
		"sys_exit:trace_sys_exit":   true,
	}
	if len(specs) != len(wantPairs) {
		t.Fatalf("raw syscall specs = %d, want %d", len(specs), len(wantPairs))
	}
	for _, spec := range specs {
		if spec.category != "raw_syscalls" {
			t.Errorf("spec category = %q, want raw_syscalls", spec.category)
		}
	}
}

func TestLifecycleTracepointSpecsAreRequired(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/bpf_attach.go"))
	for _, forbidden := range []string{"optional bool", "spec.optional"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("tracepoint attach policy still contains silent optional path %q", forbidden)
		}
	}

	specs := lifecycleTracepointSpecs(&bpfObjects{})
	want := map[string]bool{
		"sched_process_fork": true,
		"sched_process_exec": true,
		"sched_process_exit": true,
		"sched_process_free": true,
	}
	if len(specs) != len(want) {
		t.Fatalf("lifecycle specs = %d, want %d", len(specs), len(want))
	}
	for _, spec := range specs {
		if spec.category != "sched" {
			t.Errorf("lifecycle spec category = %q, want sched", spec.category)
		}
		if !want[spec.name] {
			t.Errorf("unexpected lifecycle tracepoint %q", spec.name)
		}
	}
}

func TestTracepointAttachErrorIncludesCategoryAndName(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/bpf_attach.go"))
	if !strings.Contains(source, `fmt.Errorf("attach %s/%s tracepoint: %w"`) {
		t.Fatal("tracepoint attach error must include category and name")
	}
}

func TestBPFAttacherRejectsNilObjects(t *testing.T) {
	if _, err := newBpfAttacher(nil).attachAll(); err == nil {
		t.Fatal("attachAll(nil) returned nil error")
	}
}

func TestSetSyscallVariablesResolvesAgainstSyscallTable(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf() failed: %v", err)
	}
	if err := setSyscallVariables(spec); err != nil {
		t.Fatalf("setSyscallVariables(spec) = %v, want nil", err)
	}
	// Every variable referenced by the BPF runtime must resolve to a real
	// syscall id; re-running confirms the table lookup is deterministic.
	if err := setSyscallVariables(spec); err != nil {
		t.Fatalf("second setSyscallVariables(spec) = %v, want nil", err)
	}
}
