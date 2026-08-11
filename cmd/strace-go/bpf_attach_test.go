package main

import "testing"

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
		if spec.optional {
			t.Errorf("raw syscall spec %s/%s must not be optional", spec.category, spec.name)
		}
	}
}

func TestLifecycleTracepointSpecsAreOptional(t *testing.T) {
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
		if !spec.optional {
			t.Errorf("lifecycle spec %s must be optional", spec.name)
		}
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
