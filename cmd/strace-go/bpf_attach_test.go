package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

func TestSetSyscallVariablesDoesNotUseNumericFallback(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/bpf_runtime.go"))
	for _, forbidden := range []string{
		"fallback uint32",
		"sc.fallback",
		`{"SYS_RT_SIGRETURN_COMPAT"`,
		"syscalls := []struct",
		`{"SYS_CAPGET", "capget"}`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("setSyscallVariables still contains numeric fallback %q", forbidden)
		}
	}
}

func TestSetSyscallVariablesDiscoversGeneratedRuntimeVariables(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/bpf_runtime.go"))
	for _, required := range []string{
		"spec.Variables",
		"meta.SyscallTable",
		"meta.RuntimeSyscallVariables",
		"unknown generated runtime variable",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("setSyscallVariables missing generated variable discovery marker %q", required)
		}
	}
}

func TestSetSyscallVariablesRejectsUnknownGeneratedVariable(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf() failed: %v", err)
	}
	spec.Variables["SYS_NOT_A_SYSCALL"] = &ebpf.VariableSpec{}
	err = setSyscallVariables(spec)
	if err == nil || !strings.Contains(err.Error(), "unknown generated runtime variable") {
		t.Fatalf("setSyscallVariables() error = %v, want unknown generated variable failure", err)
	}
}

func TestRuntimeSyscallVariableNamesAreSortedAndIncludeCompat(t *testing.T) {
	variables := map[string]string{
		"SYS_Z":      "z",
		"SYS_A":      "a",
		"SYS_COMPAT": "",
	}
	names := runtimeSyscallVariableNames(variables)
	want := []string{"SYS_A", "SYS_COMPAT", "SYS_Z"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("runtime variable names = %v, want %v", names, want)
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

func TestBPFCoreProgramCatalogOwnsTracepointBinding(t *testing.T) {
	program, ok := bpfCoreProgramSpecByName("trace_sys_enter")
	if !ok {
		t.Fatal("trace_sys_enter is missing from the core program catalog")
	}
	if program.category != "raw_syscalls" || program.tracepoint != "sys_enter" {
		t.Fatalf("trace_sys_enter catalog entry = %+v, want raw syscall binding", program)
	}

	program, ok = bpfCoreProgramSpecByName("trace_sched_process_exit")
	if !ok {
		t.Fatal("trace_sched_process_exit is missing from the core program catalog")
	}
	if program.category != "sched" || program.tracepoint != "sched_process_exit" {
		t.Fatalf("trace_sched_process_exit catalog entry = %+v, want lifecycle binding", program)
	}

	program, ok = bpfCoreProgramSpecByName(bpfSignalDeliverProgramName)
	if !ok {
		t.Fatal("trace_signal_deliver is missing from the core program catalog")
	}
	if program.attachKind != bpfProgramAttachRawTracepoint || program.tracepoint != "signal_deliver" {
		t.Fatalf("trace_signal_deliver catalog entry = %+v, want raw signal binding", program)
	}

	program, ok = bpfCoreProgramSpecByName(bpfSignalGenerateProgramName)
	if !ok {
		t.Fatal("trace_signal_generate is missing from the core program catalog")
	}
	if program.attachKind != bpfProgramAttachRawTracepoint || program.tracepoint != "signal_generate" {
		t.Fatalf("trace_signal_generate catalog entry = %+v, want raw signal binding", program)
	}
}

func TestSignalRawTracepointsAreRequired(t *testing.T) {
	specs := signalRawTracepointSpecs(&bpfObjects{})
	want := []string{"signal_deliver", "signal_generate"}
	if len(specs) != len(want) {
		t.Fatalf("signal raw tracepoint specs = %d, want %d", len(specs), len(want))
	}
	for index, name := range want {
		if specs[index].name != name {
			t.Fatalf("signal raw tracepoint spec %d = %q, want %q", index, specs[index].name, name)
		}
		if specs[index].program != nil {
			t.Fatalf("empty BPF objects unexpectedly exposed signal program %q", name)
		}
	}
	if _, err := attachRawTracepoint(specs[0]); err == nil || !strings.Contains(err.Error(), "program is unavailable") {
		t.Fatalf("attachRawTracepoint(nil) error = %v, want unavailable program", err)
	}
}

func TestBPFCoreProgramCatalogHasUniqueNamesAndTracepoints(t *testing.T) {
	seenNames := make(map[string]struct{})
	seenTracepoints := make(map[string]struct{})
	for _, program := range bpfCoreProgramCatalog {
		if _, exists := seenNames[program.name]; exists {
			t.Fatalf("duplicate core program name %q", program.name)
		}
		seenNames[program.name] = struct{}{}
		key := program.category + "/" + program.tracepoint
		if _, exists := seenTracepoints[key]; exists {
			t.Fatalf("duplicate core tracepoint %q", key)
		}
		seenTracepoints[key] = struct{}{}
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
