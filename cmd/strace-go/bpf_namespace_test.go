package main

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

const (
	testCloneNewCgroup   = uint64(0x02000000)
	testCloneNewIPC      = uint64(0x08000000)
	testCloneNewNS       = uint64(0x00020000)
	testCloneNewNet      = uint64(0x40000000)
	testCloneNewPID      = uint64(0x20000000)
	testCloneNewTime     = uint64(0x00000080)
	testCloneNewUTS      = uint64(0x04000000)
	testCloneNewUser     = uint64(0x10000000)
	testCloneIntoCgroup  = uint64(0x200000000)
	testNamespaceDataLen = 40
)

func TestNewTraceBPFConfigSnapshotsNamespaceNew(t *testing.T) {
	opts := cli.ParseArgs([]string{"--namespace=new", "/bin/true"})
	config := newTraceBPFConfig(opts)
	opts.NamespaceNew = false
	if !config.namespaceNew {
		t.Fatal("BPF config lost namespace=new bootstrap snapshot")
	}
}

func TestNamespaceNewSelectsOnlyNamespaceExitRoutes(t *testing.T) {
	table := map[uint32]meta.Syscall{
		1: {Name: "clone"},
		2: {Name: "clone3"},
		3: {Name: "setns"},
		4: {Name: "unshare"},
		5: {Name: "getpid"},
	}
	fullPlan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}

	plain := selectBPFRoutePlan(fullPlan, table, traceBPFConfig{})
	selected := selectBPFRoutePlan(fullPlan, table, traceBPFConfig{namespaceNew: true})
	for id := uint32(1); id <= 4; id++ {
		if plain.exit[id] == exitProgNamespace {
			t.Fatalf("plain exit route %d unexpectedly uses namespace handler", id)
		}
		if selected.exit[id] != exitProgNamespace {
			t.Fatalf("namespace exit route %d = %d, want %d", id, selected.exit[id], exitProgNamespace)
		}
	}
	if selected.exit[5] != plain.exit[5] {
		t.Fatalf("getpid exit route changed from %d to %d", plain.exit[5], selected.exit[5])
	}
}

func TestNamespaceProgramSelectionAndRawAttachmentAreOptional(t *testing.T) {
	table := map[uint32]meta.Syscall{1: {Name: "clone3"}}
	fullPlan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	plainPlan := selectBPFRoutePlan(fullPlan, table, traceBPFConfig{})
	plain, err := newBPFProgramSelection(plainPlan, table, traceBPFConfig{})
	if err != nil {
		t.Fatalf("plain selection error = %v", err)
	}
	if plain.hasProgram(bpfNamespaceForkProgramName) {
		t.Fatal("plain selection includes namespace fork program")
	}

	config := traceBPFConfig{namespaceNew: true}
	selectedPlan := selectBPFRoutePlan(fullPlan, table, config)
	selected, err := newBPFProgramSelection(selectedPlan, table, config)
	if err != nil {
		t.Fatalf("namespace selection error = %v", err)
	}
	if !selected.hasProgram(bpfNamespaceForkProgramName) || !selected.hasProgram("exit_namespace") {
		t.Fatalf("namespace selection = %#v, want raw fork and exit handler", selected.programs)
	}

	plainSpecs := requiredRawTracepointSpecs(&bpfObjects{}, plain)
	namespaceSpecs := requiredRawTracepointSpecs(&bpfObjects{}, selected)
	if rawTracepointSpecNames(plainSpecs)[bpfNamespaceForkTracepoint] {
		t.Fatal("plain attachment includes namespace fork tracepoint")
	}
	if !rawTracepointSpecNames(namespaceSpecs)[bpfNamespaceForkTracepoint] {
		t.Fatal("namespace attachment is missing sched_process_fork raw tracepoint")
	}
}

func TestNamespacePayloadTLVDecodesSemanticKind(t *testing.T) {
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindNamespace,
		arg:     payloadTLVNamespaceArgIndex,
		flags:   payloadTLVFlagDirectionOut,
		userLen: namespaceSnapshotSize,
		data:    namespaceSnapshotBytes(testCloneNewUser, [8]uint32{}),
	})
	sections := payloadSectionsForRawPayloadEvent(rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		data:       payload,
	})
	if len(sections) != 1 || sections[0].Kind != handler.PayloadKindNamespace {
		t.Fatalf("namespace TLV sections = %+v", sections)
	}
}

func TestNamespaceReturnDescriptionUsesUpstreamOrder(t *testing.T) {
	flags := testCloneNewCgroup | testCloneIntoCgroup | testCloneNewIPC |
		testCloneNewNS | testCloneNewNet | testCloneNewPID | testCloneNewTime |
		testCloneNewUTS | testCloneNewUser
	data := namespaceSnapshotBytes(flags, [8]uint32{11, 12, 13, 14, 15, 16, 17, 18})
	ctx := &handler.Context{
		Ret: 0,
		PayloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindNamespace,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  payloadTLVNamespaceArgIndex,
			CopiedLen: uint32(len(data)),
			Data:      data,
		}},
	}
	want := "cgroup:[11], ipc:[12], mnt:[13], net:[14], pid:[15], time:[16], uts:[17], user:[18]"
	if got := namespaceReturnDescription(ctx); got != want {
		t.Fatalf("namespace return = %q, want %q", got, want)
	}
}

func TestNamespaceReturnDescriptionRejectsFailureAndMalformedPayload(t *testing.T) {
	data := namespaceSnapshotBytes(testCloneNewUser, [8]uint32{0, 0, 0, 0, 0, 0, 0, 18})
	section := handler.PayloadSection{
		Kind:      handler.PayloadKindNamespace,
		Direction: handler.PayloadDirectionOut,
		ArgIndex:  payloadTLVNamespaceArgIndex,
		CopiedLen: uint32(len(data)),
		Data:      data,
	}
	if got := namespaceReturnDescription(&handler.Context{Ret: -1, PayloadSections: []handler.PayloadSection{section}}); got != "" {
		t.Fatalf("failed syscall namespace return = %q, want empty", got)
	}
	section.Data = section.Data[:len(section.Data)-1]
	section.CopiedLen--
	if got := namespaceReturnDescription(&handler.Context{Ret: 0, PayloadSections: []handler.PayloadSection{section}}); got != "" {
		t.Fatalf("malformed namespace return = %q, want empty", got)
	}
}

func TestSyscallHandlerRunnerDecoratesNamespaceReturn(t *testing.T) {
	data := namespaceSnapshotBytes(testCloneNewUser, [8]uint32{0, 0, 0, 0, 0, 0, 0, 108})
	event := handlerRunnerEvent("clone3", true)
	event.handlerContext.Ret = 42
	event.handlerContext.PayloadSections = []handler.PayloadSection{{
		Kind:      handler.PayloadKindNamespace,
		Direction: handler.PayloadDirectionOut,
		ArgIndex:  payloadTLVNamespaceArgIndex,
		CopiedLen: uint32(len(data)),
		Data:      data,
	}}
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(string, *handler.Context) handler.Result {
			return handler.Result{ArgParts: []string{"clone args"}}
		},
	})
	result, shouldOutput := runner.Handle(event)
	if !shouldOutput || result.ReturnDesc != "user:[108]" {
		t.Fatalf("runner result = %+v/%v, want namespace auxstr", result, shouldOutput)
	}
}

func TestNamespaceBPFSourceOwnsChildSnapshotAndExitTLV(t *testing.T) {
	root := repoRootForTest(t)
	sources := map[string]string{
		"core":    readTextFile(t, filepath.Join(root, "bpf/namespace_dispatch.h")),
		"capture": readTextFile(t, filepath.Join(root, "bpf/syscall_namespace_direct_event_v2.h")),
		"exit":    readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h")),
	}
	for name, snippets := range map[string][]string{
		"core": {
			`SEC("raw_tracepoint/sched_process_fork")`,
			"ctx->args[1]",
			"state->namespace_snapshot",
		},
		"capture": {
			"PAYLOAD_TLV_KIND_NAMESPACE",
			"read_namespace_snapshot",
			"emit_namespace_exit_event_v2_direct",
		},
		"exit": {
			"int exit_namespace(",
			"emit_namespace_exit_event_v2_direct",
			"consume_pending_syscall",
		},
	} {
		for _, snippet := range snippets {
			if !strings.Contains(sources[name], snippet) {
				t.Fatalf("%s namespace source missing %q", name, snippet)
			}
		}
	}
}

func namespaceSnapshotBytes(flags uint64, ids [8]uint32) []byte {
	data := make([]byte, testNamespaceDataLen)
	binary.LittleEndian.PutUint64(data[0:8], flags)
	for index, id := range ids {
		binary.LittleEndian.PutUint32(data[8+index*4:12+index*4], id)
	}
	return data
}

func rawTracepointSpecNames(specs []rawTracepointSpec) map[string]bool {
	names := make(map[string]bool, len(specs))
	for _, spec := range specs {
		names[spec.name] = true
	}
	return names
}
