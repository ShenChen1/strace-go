package main

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBPFMapReplacementPlanRejectsNilInputs(t *testing.T) {
	if _, err := newBPFMapReplacementPlan(nil, &ebpf.CollectionSpec{}); err == nil {
		t.Fatal("nil core collection must fail")
	}
	if _, err := newBPFMapReplacementPlan(&ebpf.Collection{}, nil); err == nil {
		t.Fatal("nil handler spec must fail")
	}
}

func TestBPFMapReplacementPlanRequiresCoreRuntimeMaps(t *testing.T) {
	core := &ebpf.Collection{Maps: map[string]*ebpf.Map{"events": {}}}
	handlers := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"events":           {Type: ebpf.RingBuf, MaxEntries: 4096},
		"pending_syscalls": {Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 8},
	}}

	_, err := newBPFMapReplacementPlan(core, handlers)
	if err == nil || !strings.Contains(err.Error(), `core map "pending_syscalls" is unavailable`) {
		t.Fatalf("replacement plan error = %v, want missing core map", err)
	}
}

func TestBPFMapReplacementPlanExcludesDataSections(t *testing.T) {
	core := &ebpf.Collection{Maps: map[string]*ebpf.Map{
		"events":  {},
		".rodata": {},
		".bss":    {},
	}}
	handlers := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"events":  {Type: ebpf.RingBuf, MaxEntries: 4096},
		".rodata": {Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
		".bss":    {Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
	}}

	plan, err := newBPFMapReplacementPlan(core, handlers)
	if err != nil {
		t.Fatalf("newBPFMapReplacementPlan() error = %v", err)
	}
	if len(plan.replacements) != 1 {
		t.Fatalf("replacement count = %d, want 1", len(plan.replacements))
	}
	if plan.replacements["events"] == nil {
		t.Fatal("events replacement is missing")
	}
	for _, name := range []string{".rodata", ".bss"} {
		if _, ok := plan.replacements[name]; ok {
			t.Fatalf("data section %q must not be replaced", name)
		}
	}
}

func TestClassifyBPFHandlerProgram(t *testing.T) {
	tests := []struct {
		name   string
		family bpfHandlerFamily
		valid  bool
	}{
		{name: "enter_no_payload_direct", family: bpfHandlerEnterPathFamily, valid: true},
		{name: "exit_generic", family: bpfHandlerExitFamily, valid: true},
		{name: "exit_nested_fd_path3", family: bpfHandlerExitFamily, valid: true},
		{name: "trace_kretprobe_recvmsg_dispatch", family: bpfHandlerRecvmsgFamily, valid: true},
		{name: "trace_sys_enter", valid: false},
		{name: "unknown_handler", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			family, ok := classifyBPFHandlerProgram(test.name)
			if ok != test.valid || (ok && family != test.family) {
				t.Fatalf("classifyBPFHandlerProgram(%q) = (%q, %v), want (%q, %v)", test.name, family, ok, test.family, test.valid)
			}
		})
	}
}

func TestClassifyBPFEnterProgramsByCapability(t *testing.T) {
	tests := []struct {
		name   string
		family bpfHandlerFamily
	}{
		{name: "enter_no_payload_generic", family: bpfHandlerFamily("enter_generic")},
		{name: "enter_payload_direct", family: bpfHandlerFamily("enter_payload")},
		{name: "enter_path_only", family: bpfHandlerFamily("enter_path")},
		{name: "enter_iovec_base", family: bpfHandlerFamily("enter_memory")},
		{name: "enter_network", family: bpfHandlerFamily("enter_control")},
		{name: "enter_nested_fd_path3", family: bpfHandlerFamily("enter_control")},
		{name: "enter_capability", family: bpfHandlerFamily("enter_structured")},
		{name: "enter_mmsg_bytes3", family: bpfHandlerFamily("enter_memory")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			family, ok := classifyBPFHandlerProgram(test.name)
			if !ok || family != test.family {
				t.Fatalf("classifyBPFHandlerProgram(%q) = (%q, %v), want (%q, true)", test.name, family, ok, test.family)
			}
		})
	}
}

func TestClassifyBPFHandlerProgramRejectsUnownedEnterProgram(t *testing.T) {
	for _, name := range []string{"enter_future", "enter_unknown_fragment"} {
		if family, ok := classifyBPFHandlerProgram(name); ok {
			t.Fatalf("classifyBPFHandlerProgram(%q) = (%q, true), want rejected", name, family)
		}
	}
}

func TestBPFEnterCapabilityLoadOrder(t *testing.T) {
	want := []bpfHandlerFamily{
		bpfHandlerFamily("enter_generic"),
		bpfHandlerFamily("enter_payload"),
		bpfHandlerFamily("enter_path"),
		bpfHandlerFamily("enter_memory"),
		bpfHandlerFamily("enter_control"),
		bpfHandlerFamily("enter_structured"),
		bpfHandlerExitFamily,
		bpfHandlerRecvmsgFamily,
	}
	got := make([]bpfHandlerFamily, 0, len(bpfHandlerFamilyCatalog))
	for _, spec := range bpfHandlerFamilyCatalog {
		got = append(got, spec.family)
	}
	if !equalHandlerFamilies(got, want) {
		t.Fatalf("handler load order = %v, want %v", got, want)
	}
}

func TestPrepareBPFCollectionProgramsSplitsSelectedFamilies(t *testing.T) {
	core := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"trace_sys_enter": {},
	}}
	handlers := map[bpfHandlerFamily]*ebpf.CollectionSpec{
		bpfHandlerEnterPathFamily: {Programs: map[string]*ebpf.ProgramSpec{
			"enter_no_payload_direct": {},
		}},
		bpfHandlerEnterControlFamily: {Programs: map[string]*ebpf.ProgramSpec{
			"enter_network": {},
		}},
		bpfHandlerExitFamily: {Programs: map[string]*ebpf.ProgramSpec{
			"exit_generic": {},
			"exit_io":      {},
		}},
		bpfHandlerRecvmsgFamily: {Programs: map[string]*ebpf.ProgramSpec{
			"trace_kretprobe_recvmsg_dispatch": {},
		}},
	}
	selection := bpfProgramSelection{programs: map[string]struct{}{
		"trace_sys_enter":                  {},
		"enter_no_payload_direct":          {},
		"enter_network":                    {},
		"exit_generic":                     {},
		"trace_kretprobe_recvmsg_dispatch": {},
	}}

	if err := prepareBPFCollectionPrograms(core, handlers, selection); err != nil {
		t.Fatalf("prepareBPFCollectionPrograms() error = %v", err)
	}
	if len(handlers[bpfHandlerEnterPathFamily].Programs) != 1 {
		t.Fatalf("path programs = %d, want 1", len(handlers[bpfHandlerEnterPathFamily].Programs))
	}
	if len(handlers[bpfHandlerEnterControlFamily].Programs) != 1 {
		t.Fatalf("control programs = %d, want 1", len(handlers[bpfHandlerEnterControlFamily].Programs))
	}
	if len(handlers[bpfHandlerExitFamily].Programs) != 1 {
		t.Fatalf("exit programs = %d, want 1", len(handlers[bpfHandlerExitFamily].Programs))
	}
	if len(handlers[bpfHandlerRecvmsgFamily].Programs) != 1 {
		t.Fatalf("recvmsg programs = %d, want 1", len(handlers[bpfHandlerRecvmsgFamily].Programs))
	}
}

func TestPrepareBPFCollectionProgramsRejectsUnclassifiedSelection(t *testing.T) {
	core := &ebpf.CollectionSpec{}
	handlers := map[bpfHandlerFamily]*ebpf.CollectionSpec{
		bpfHandlerEnterControlFamily: {Programs: map[string]*ebpf.ProgramSpec{"enter_network": {}}},
	}
	selection := bpfProgramSelection{programs: map[string]struct{}{"mystery": {}}}

	err := prepareBPFCollectionPrograms(core, handlers, selection)
	if err == nil || !strings.Contains(err.Error(), `selected BPF program "mystery" is unavailable`) {
		t.Fatalf("prepareBPFCollectionPrograms() error = %v, want unavailable program", err)
	}
}

func TestPrepareBPFCollectionProgramsRejectsUnknownSelectionInLoadAllMode(t *testing.T) {
	core := &ebpf.CollectionSpec{}
	handlers := map[bpfHandlerFamily]*ebpf.CollectionSpec{
		bpfHandlerEnterGenericFamily: {Programs: map[string]*ebpf.ProgramSpec{"enter_no_payload_generic": {}}},
	}
	selection := bpfProgramSelection{
		loadAll:  true,
		programs: map[string]struct{}{"enter_future": {}},
	}

	err := prepareBPFCollectionPrograms(core, handlers, selection)
	if err == nil || !strings.Contains(err.Error(), `selected BPF program "enter_future" is unavailable`) {
		t.Fatalf("prepareBPFCollectionPrograms() error = %v, want unavailable program", err)
	}
}

type orderedBPFCloser struct {
	name  string
	order *[]string
}

func (c *orderedBPFCloser) Close() error {
	*c.order = append(*c.order, c.name)
	return nil
}

func TestBPFLoadedHandlerCollectionsCloseInReverseLoadOrder(t *testing.T) {
	var order []string
	loaded := &bpfLoadedHandlerCollections{
		collections: map[bpfHandlerFamily]*bpfLoadedCollection{
			bpfHandlerEnterGenericFamily: {
				closer: &orderedBPFCloser{name: "enter", order: &order},
			},
			bpfHandlerExitFamily: {
				closer: &orderedBPFCloser{name: "exit", order: &order},
			},
		},
		loadOrder: []bpfHandlerFamily{bpfHandlerEnterGenericFamily, bpfHandlerExitFamily},
	}

	if err := loaded.Close(); err != nil {
		t.Fatalf("BPF handler collection close = %v", err)
	}
	if got, want := strings.Join(order, ","), "exit,enter"; got != want {
		t.Fatalf("close order = %q, want %q", got, want)
	}
}
