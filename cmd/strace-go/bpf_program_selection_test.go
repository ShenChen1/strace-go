package main

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

func TestBPFProgramSelectionKeepsPositiveFilterDependencies(t *testing.T) {
	table := map[uint32]meta.Syscall{
		1: {Name: "getpid"},
		2: {Name: "write"},
		3: {Name: "recvmsg"},
	}
	fullPlan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	config := traceBPFConfig{
		syscallFilter: syscallFilterPlan{enabled: true, ids: []uint32{1}},
	}
	plan := selectBPFRoutePlan(fullPlan, config)
	selection, err := newBPFProgramSelection(plan, table, config)
	if err != nil {
		t.Fatalf("newBPFProgramSelection() error = %v", err)
	}

	if selection.loadAll {
		t.Fatal("positive filter selected all BPF programs")
	}
	for _, name := range []string{
		"trace_sys_enter",
		"trace_sys_exit",
		"trace_sched_process_fork",
		"trace_sched_process_exec",
		"trace_sched_process_exit",
		"trace_sched_process_free",
		"enter_no_payload_direct",
		"exit_generic",
	} {
		if !selection.hasProgram(name) {
			t.Fatalf("selection missing required program %q", name)
		}
	}
	for _, name := range []string{"enter_payload_direct", "enter_network", "trace_kretprobe_recvmsg_dispatch"} {
		if selection.hasProgram(name) {
			t.Fatalf("selection unexpectedly includes program %q", name)
		}
	}
}

func TestBPFProgramSelectionIncludesTailCallDependencies(t *testing.T) {
	table := map[uint32]meta.Syscall{
		1: {Name: "recvmmsg"},
	}
	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	selection, err := newBPFProgramSelection(plan, table, traceBPFConfig{
		syscallFilter: syscallFilterPlan{enabled: true, ids: []uint32{1}},
	})
	if err != nil {
		t.Fatalf("newBPFProgramSelection() error = %v", err)
	}

	for _, name := range []string{
		"enter_mmsg",
		"enter_mmsg_base01",
		"enter_mmsg_base2",
		"enter_mmsg_base3",
		"exit_recvmmsg_base01",
		"exit_recvmmsg_base23",
		"exit_mmsg_final",
	} {
		if !selection.hasProgram(name) {
			t.Fatalf("mmsg selection missing tail-call dependency %q", name)
		}
	}
	for _, name := range []string{"enter_mmsg_bytes0", "enter_mmsg_bytes3"} {
		if selection.hasProgram(name) {
			t.Fatalf("recvmmsg selection unexpectedly includes sendmmsg-only program %q", name)
		}
	}
}

func TestBPFProgramSelectionIncludesAIOFragmentDependencies(t *testing.T) {
	table := map[uint32]meta.Syscall{
		1: {Name: "io_submit"},
	}
	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	selection, err := newBPFProgramSelection(plan, table, traceBPFConfig{
		syscallFilter: syscallFilterPlan{enabled: true, ids: []uint32{1}},
	})
	if err != nil {
		t.Fatalf("newBPFProgramSelection() error = %v", err)
	}
	for _, name := range []string{"enter_aio", "enter_aio_iovec", "enter_aio_buf"} {
		if !selection.hasProgram(name) {
			t.Fatalf("AIO selection missing tail-call dependency %q", name)
		}
	}
}

func TestBPFProgramSelectionUsesConservativeModes(t *testing.T) {
	plan := bpfRoutePlan{
		enter: map[uint32]uint32{1: enterProgNoPayload},
		exit:  map[uint32]uint32{1: exitProgGeneric},
	}
	tests := []traceBPFConfig{
		{},
		{syscallFilter: syscallFilterPlan{enabled: true, negated: true, ids: []uint32{1}}},
		{fdState: true, syscallFilter: syscallFilterPlan{enabled: true, ids: []uint32{1}}},
	}
	for index, config := range tests {
		selected := selectBPFRoutePlan(plan, config)
		selection, err := newBPFProgramSelection(selected, map[uint32]meta.Syscall{1: {Name: "getpid"}}, config)
		if err != nil {
			t.Fatalf("case %d newBPFProgramSelection() error = %v", index, err)
		}
		if !selection.loadAll {
			t.Fatalf("case %d selected selective loading, want conservative full loading", index)
		}
		if len(selected.enter) != len(plan.enter) || len(selected.exit) != len(plan.exit) {
			t.Fatalf("case %d route plan was narrowed in conservative mode: %+v", index, selected)
		}
	}
}

func TestPruneBPFProgramSpecsRemovesUnselectedPrograms(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"keep":   {},
		"remove": {},
	}}
	selection := bpfProgramSelection{programs: map[string]struct{}{"keep": {}}}
	if err := pruneBPFProgramSpecs(spec, selection); err != nil {
		t.Fatalf("pruneBPFProgramSpecs() error = %v", err)
	}
	if _, ok := spec.Programs["remove"]; ok {
		t.Fatal("pruneBPFProgramSpecs() kept unselected program")
	}
}

func TestPruneBPFProgramSpecsRejectsMissingSelection(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"keep": {}}}
	selection := bpfProgramSelection{programs: map[string]struct{}{"missing": {}}}
	err := pruneBPFProgramSpecs(spec, selection)
	if err == nil || !strings.Contains(err.Error(), `selected BPF program "missing" is unavailable`) {
		t.Fatalf("pruneBPFProgramSpecs() error = %v, want missing program error", err)
	}
}

func TestBPFProgramSelectionRejectsUnknownRouteSlot(t *testing.T) {
	plan := bpfRoutePlan{
		enter: map[uint32]uint32{1: 999},
		exit:  map[uint32]uint32{1: exitProgGeneric},
	}
	config := traceBPFConfig{
		syscallFilter: syscallFilterPlan{enabled: true, ids: []uint32{1}},
	}
	_, err := newBPFProgramSelection(plan, map[uint32]meta.Syscall{1: {Name: "getpid"}}, config)
	if err == nil || !strings.Contains(err.Error(), "unknown BPF enter program slot 999") {
		t.Fatalf("newBPFProgramSelection() error = %v, want unknown slot error", err)
	}
}

func TestBPFProgramSelectionCatalogMatchesGeneratedSpec(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf() error = %v", err)
	}
	for _, name := range []string{
		"trace_sys_enter",
		"trace_sys_exit",
		"trace_sched_process_fork",
		"trace_sched_process_exec",
		"trace_sched_process_exit",
		"trace_sched_process_free",
	} {
		if spec.Programs[name] == nil {
			t.Fatalf("generated BPF spec is missing core program %q", name)
		}
	}
	for slot, name := range bpfEnterProgramNames {
		if spec.Programs[name] == nil {
			t.Fatalf("generated BPF spec is missing enter slot %d program %q", slot, name)
		}
	}
	for slot, name := range bpfExitProgramNames {
		if spec.Programs[name] == nil {
			t.Fatalf("generated BPF spec is missing exit slot %d program %q", slot, name)
		}
	}
	for slot, name := range bpfRecvmsgProgramNames {
		if spec.Programs[name] == nil {
			t.Fatalf("generated BPF spec is missing recvmsg slot %d program %q", slot, name)
		}
	}
	for slot, name := range bpfMmsgByteProgramNames {
		if spec.Programs[name] == nil {
			t.Fatalf("generated BPF spec is missing mmsg byte slot %d program %q", slot, name)
		}
	}
}

func TestSelectedProgArrayEntriesKeepOnlyRequestedSlots(t *testing.T) {
	entries := []progArrayEntry{{index: 1}, {index: 3}, {index: 5}}
	selected := selectedProgArrayEntries(entries, map[uint32]struct{}{3: {}}, false)
	if len(selected) != 1 || selected[0].index != 3 {
		t.Fatalf("selected entries = %+v, want only slot 3", selected)
	}
}
