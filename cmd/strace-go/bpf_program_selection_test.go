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
	plan := selectBPFRoutePlan(fullPlan, table, config)
	selection, err := newBPFProgramSelection(plan, table, config)
	if err != nil {
		t.Fatalf("newBPFProgramSelection() error = %v", err)
	}

	if selection.loadAll {
		t.Fatal("positive filter selected all BPF programs")
	}
	for _, program := range bpfCoreProgramCatalog {
		if program.feature != bpfProgramFeatureRequired {
			continue
		}
		if !selection.hasProgram(program.name) {
			t.Fatalf("selection missing required core program %q", program.name)
		}
	}
	for _, name := range []string{
		"enter_no_payload_generic",
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

func TestBPFProgramSelectionUsesGenericNoPayloadWithoutFDState(t *testing.T) {
	table := map[uint32]meta.Syscall{1: {Name: "getpid"}}
	fullPlan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	config := traceBPFConfig{
		syscallFilter: syscallFilterPlan{enabled: true, ids: []uint32{1}},
	}
	plan := selectBPFRoutePlan(fullPlan, table, config)
	if got := plan.enter[1]; got != enterProgNoPayloadGeneric {
		t.Fatalf("plain enter route = %d, want generic slot %d", got, enterProgNoPayloadGeneric)
	}
	selection, err := newBPFProgramSelection(plan, table, config)
	if err != nil {
		t.Fatalf("newBPFProgramSelection() error = %v", err)
	}
	if !selection.hasProgram("enter_no_payload_generic") {
		t.Fatal("plain selection is missing generic no-payload handler")
	}
	if selection.hasProgram("enter_no_payload_direct") {
		t.Fatal("plain selection retained FD/path-aware no-payload handler")
	}
}

func TestBPFProgramSelectionKeepsFDStateNoPayloadHandler(t *testing.T) {
	table := map[uint32]meta.Syscall{1: {Name: "getpid"}}
	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	config := traceBPFConfig{
		fdState:       true,
		syscallFilter: syscallFilterPlan{enabled: true, ids: []uint32{1}},
	}
	selectedPlan := selectBPFRoutePlan(plan, table, config)
	if got := selectedPlan.enter[1]; got != enterProgNoPayload {
		t.Fatalf("FD-state enter route = %d, want path-aware slot %d", got, enterProgNoPayload)
	}
	selection, err := newBPFProgramSelection(selectedPlan, table, config)
	if err != nil {
		t.Fatalf("newBPFProgramSelection() error = %v", err)
	}
	if !selection.loadAll {
		t.Fatal("FD-state selection must keep conservative full loading")
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

func TestBPFProgramSelectionIncludesBPFDynamicDependencies(t *testing.T) {
	table := map[uint32]meta.Syscall{1: {Name: "bpf"}}
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
	for _, name := range []string{"enter_bpf", "enter_bpf_uprobe_multi", "enter_bpf_prog_load", "enter_bpf_prog_load_debug"} {
		if !selection.hasProgram(name) {
			t.Fatalf("BPF selection missing dynamic tail-call dependency %q", name)
		}
	}
	for _, slot := range []uint32{enterProgBpf, enterProgBpfUprobeMulti, enterProgBpfProgLoad, enterProgBpfProgLoadDebug} {
		if _, ok := selection.enterSlots[slot]; !ok {
			t.Fatalf("BPF selection missing dynamic tail-call slot %d", slot)
		}
	}
}

func TestBPFProgramSelectionPrunesFullRouteClosureWithoutFDState(t *testing.T) {
	table := map[uint32]meta.Syscall{1: {Name: "getpid"}}
	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	config := traceBPFConfig{}
	selectedPlan := selectBPFRoutePlan(plan, table, config)
	selection, err := newBPFProgramSelection(selectedPlan, table, config)
	if err != nil {
		t.Fatalf("newBPFProgramSelection() error = %v", err)
	}
	if selection.loadAll {
		t.Fatal("plain full route closure unexpectedly selected load-all mode")
	}
	if !selection.hasProgram("enter_no_payload_generic") {
		t.Fatal("plain full route closure is missing generic no-payload handler")
	}
	if selection.hasProgram("enter_no_payload_direct") {
		t.Fatal("plain full route closure retained unreachable FD/path-aware handler")
	}
}

func TestBPFProgramSelectionPrunesNegatedFilterClosureWithoutFDState(t *testing.T) {
	table := map[uint32]meta.Syscall{1: {Name: "getpid"}}
	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	config := traceBPFConfig{
		syscallFilter: syscallFilterPlan{enabled: true, negated: true, ids: []uint32{1}},
	}
	selectedPlan := selectBPFRoutePlan(plan, table, config)
	selection, err := newBPFProgramSelection(selectedPlan, table, config)
	if err != nil {
		t.Fatalf("newBPFProgramSelection() error = %v", err)
	}
	if selection.loadAll {
		t.Fatal("negated full route closure unexpectedly selected load-all mode")
	}
}

func TestBPFProgramSelectionUsesConservativeModes(t *testing.T) {
	plan := bpfRoutePlan{
		enter: map[uint32]uint32{1: enterProgNoPayload},
		exit:  map[uint32]uint32{1: exitProgGeneric},
	}
	tests := []struct {
		config  traceBPFConfig
		wantAll bool
	}{
		{config: traceBPFConfig{}, wantAll: false},
		{config: traceBPFConfig{
			syscallFilter: syscallFilterPlan{enabled: true, negated: true, ids: []uint32{1}},
		}, wantAll: false},
		{config: traceBPFConfig{
			fdState:       true,
			syscallFilter: syscallFilterPlan{enabled: true, ids: []uint32{1}},
		}, wantAll: true},
	}
	for index, test := range tests {
		selected := selectBPFRoutePlan(plan, map[uint32]meta.Syscall{1: {Name: "getpid"}}, test.config)
		selection, err := newBPFProgramSelection(selected, map[uint32]meta.Syscall{1: {Name: "getpid"}}, test.config)
		if err != nil {
			t.Fatalf("case %d newBPFProgramSelection() error = %v", index, err)
		}
		if selection.loadAll != test.wantAll {
			t.Fatalf("case %d loadAll = %v, want %v", index, selection.loadAll, test.wantAll)
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
	coreSpec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf() error = %v", err)
	}
	for _, program := range bpfCoreProgramCatalog {
		if coreSpec.Programs[program.name] == nil {
			t.Fatalf("generated BPF spec is missing core program %q", program.name)
		}
	}
	handlerSpecs, err := loadBPFHandlerSpecs()
	if err != nil {
		t.Fatalf("load BPF handler specs: %v", err)
	}
	for _, program := range bpfEnterProgramCatalog {
		family, ok := bpfHandlerProgramFamilies[program.name]
		if !ok || handlerSpecs[family].Programs[program.name] == nil {
			t.Fatalf("generated BPF spec is missing enter slot %d program %q in family %q", program.slot, program.name, family)
		}
	}
	for _, program := range bpfExitProgramCatalog {
		if handlerSpecs[bpfHandlerExitFamily].Programs[program.name] == nil {
			t.Fatalf("generated BPF spec is missing exit slot %d program %q", program.slot, program.name)
		}
	}
	for _, program := range bpfRecvmsgProgramCatalog {
		if handlerSpecs[bpfHandlerRecvmsgFamily].Programs[program.name] == nil {
			t.Fatalf("generated BPF spec is missing recvmsg slot %d program %q", program.slot, program.name)
		}
	}
	for _, program := range bpfMmsgByteProgramCatalog {
		family, ok := bpfHandlerProgramFamilies[program.name]
		if !ok || handlerSpecs[family].Programs[program.name] == nil {
			t.Fatalf("generated BPF spec is missing mmsg byte slot %d program %q", program.slot, program.name)
		}
	}
	for _, program := range bpfStandaloneProgramCatalog {
		if handlerSpecs[program.family].Programs[program.name] == nil {
			t.Fatalf("generated BPF spec is missing standalone program %q in family %q", program.name, program.family)
		}
	}
}

func TestBPFEnterProgramOwnershipIsExclusive(t *testing.T) {
	handlerSpecs, err := loadBPFHandlerSpecs()
	if err != nil {
		t.Fatalf("load BPF handler specs: %v", err)
	}
	enterFamilies := make(map[bpfHandlerFamily]struct{})
	for _, program := range bpfEnterProgramCatalog {
		enterFamilies[program.family] = struct{}{}
	}
	owners := make(map[string]bpfHandlerFamily)
	for family := range enterFamilies {
		spec := handlerSpecs[family]
		if spec == nil {
			t.Fatalf("missing handler spec for enter family %q", family)
		}
		for name := range spec.Programs {
			if previous, exists := owners[name]; exists {
				t.Fatalf("enter program %q is owned by %q and %q", name, previous, family)
			}
			owners[name] = family
			if want := bpfHandlerProgramFamilies[name]; want != family {
				t.Fatalf("enter program %q owner = %q, want %q", name, family, want)
			}
		}
	}
	for _, program := range bpfEnterProgramCatalog {
		if _, ok := owners[program.name]; !ok {
			t.Fatalf("enter slot %d program %q has no capability owner", program.slot, program.name)
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

func TestBPFProgramCatalogOwnsSlotNameAndFamily(t *testing.T) {
	program, ok := bpfTailCallProgramBySlot(bpfEnterProgramCatalog, enterProgEpoll)
	if !ok {
		t.Fatal("enter epoll program is missing from the catalog")
	}
	if program.name != "enter_epoll" || program.family != bpfHandlerEnterControlFamily {
		t.Fatalf("enter epoll catalog entry = %+v, want name and control family", program)
	}

	program, ok = bpfTailCallProgramBySlot(bpfExitProgramCatalog, exitProgNestedFDPath3)
	if !ok {
		t.Fatal("exit nested path program is missing from the catalog")
	}
	if program.name != "exit_nested_fd_path3" || program.family != bpfHandlerExitFamily {
		t.Fatalf("exit nested path catalog entry = %+v, want name and exit family", program)
	}
}

func TestBPFProgramCatalogHasUniqueSlotAndNameEntries(t *testing.T) {
	seenNames := make(map[string]struct{})
	for _, catalog := range [][]bpfTailCallProgramSpec{
		bpfEnterProgramCatalog,
		bpfExitProgramCatalog,
		bpfRecvmsgProgramCatalog,
		bpfMmsgByteProgramCatalog,
	} {
		seenSlots := make(map[uint32]struct{})
		for _, program := range catalog {
			if _, exists := seenSlots[program.slot]; exists {
				t.Fatalf("duplicate slot %d in catalog", program.slot)
			}
			seenSlots[program.slot] = struct{}{}
			if _, exists := seenNames[program.name]; exists {
				t.Fatalf("program %q appears in multiple catalogs", program.name)
			}
			seenNames[program.name] = struct{}{}
		}
	}
	for _, program := range bpfStandaloneProgramCatalog {
		if _, exists := seenNames[program.name]; exists {
			t.Fatalf("program %q appears in multiple catalogs", program.name)
		}
		seenNames[program.name] = struct{}{}
	}
}
