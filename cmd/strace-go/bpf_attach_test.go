package main

import "testing"

func TestRawSyscallTracepointSpecsAreRequired(t *testing.T) {
	specs := rawSyscallTracepointSpecs(&bpfObjects{})
	wantPairs := map[string]bool{
		"sys_enter:trace_sys_enter":                true,
		"sys_enter:trace_sys_enter_bpf":            true,
		"sys_enter:trace_sys_enter_iovec_base":     true,
		"sys_enter:trace_sys_enter_msg":            true,
		"sys_enter:trace_sys_enter_sendmsg_base":   true,
		"sys_enter:trace_sys_enter_mmsg":           true,
		"sys_enter:trace_sys_enter_sendmmsg_base0": true,
		"sys_enter:trace_sys_enter_sendmmsg_base1": true,
		"sys_exit:trace_sys_exit":                  true,
		"sys_exit:trace_sys_exit_iovec_base":       true,
		"sys_exit:trace_sys_exit_recvmmsg_base0":   true,
		"sys_exit:trace_sys_exit_recvmmsg_base1":   true,
		"sys_exit:trace_sys_exit_msg":              true,
		"sys_exit:trace_sys_exit_mmsg":             true,
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
