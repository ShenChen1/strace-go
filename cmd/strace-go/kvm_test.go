package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestNewTraceBPFConfigSnapshotsKVMExitReason(t *testing.T) {
	opts := cli.ParseArgs([]string{"--kvm=vcpu", "/bin/true"})
	config := newTraceBPFConfig(opts)
	opts.KVMExitReason = false
	if !config.kvmExitReason {
		t.Fatal("BPF config lost KVM exit-reason bootstrap snapshot")
	}

	value, err := buildRuntimeConfig(traceBPFConfig{kvmExitReason: true}, nil)
	if err != nil {
		t.Fatalf("buildRuntimeConfig(KVM) error = %v", err)
	}
	if value&bpfConfigKVMExit == 0 {
		t.Fatalf("runtime config = %#x, want KVM exit bit", value)
	}
}

func TestKVMProgramSelectionIsExplicit(t *testing.T) {
	table := map[uint32]meta.Syscall{1: {Name: "ioctl"}}
	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}

	enabled, err := newBPFProgramSelection(plan, table, traceBPFConfig{kvmExitReason: true})
	if err != nil {
		t.Fatalf("KVM selection error = %v", err)
	}
	if !enabled.kvmExitReason || !enabled.hasProgram(bpfKVMUserspaceExitProgramName) {
		t.Fatalf("KVM selection = %#v, want userspace-exit program", enabled)
	}

	disabled, err := newBPFProgramSelection(plan, table, traceBPFConfig{})
	if err != nil {
		t.Fatalf("plain selection error = %v", err)
	}
	if disabled.kvmExitReason || disabled.hasProgram(bpfKVMUserspaceExitProgramName) {
		t.Fatalf("plain selection unexpectedly enabled KVM: %#v", disabled)
	}
}

func TestKVMTracepointSpecsFollowSelection(t *testing.T) {
	disabled := kvmTracepointSpecs(&bpfObjects{}, bpfProgramSelection{})
	if len(disabled) != 0 {
		t.Fatalf("disabled KVM specs = %+v, want none", disabled)
	}

	enabled := kvmTracepointSpecs(&bpfObjects{}, bpfProgramSelection{kvmExitReason: true})
	if len(enabled) != 1 || enabled[0].category != "kvm" || enabled[0].name != "kvm_userspace_exit" {
		t.Fatalf("enabled KVM specs = %+v, want kvm/kvm_userspace_exit", enabled)
	}
}

func TestKVMExitReasonDecoratesSuccessfulRun(t *testing.T) {
	state := newHandlerRunnerTestState(handler.Result{ArgParts: []string{"3", "KVM_RUN", "0"}})
	event := handlerRunnerEvent("ioctl", true)
	event.view.eventType = bpfEventTypeExit
	event.view.eventFlags = bpfEventFlagKVMExit
	event.view.args[1] = kvmRunIOCTL
	event.view.ret = 0
	event.view.kvmExitReason = 2

	result, shouldOutput := state.runner.Handle(event)
	if !shouldOutput || result.ReturnDesc != "KVM_EXIT_IO" {
		t.Fatalf("KVM result = %+v, output=%v; want KVM_EXIT_IO", result, shouldOutput)
	}
}

func TestKVMExitReasonRejectsInapplicableEvents(t *testing.T) {
	tests := []syscallEventView{
		{eventType: bpfEventTypeExit, eventFlags: bpfEventFlagKVMExit, args: [6]uint64{0, kvmRunIOCTL}, ret: -1, kvmExitReason: 2},
		{eventType: bpfEventTypeExit, eventFlags: bpfEventFlagKVMExit, args: [6]uint64{0, 0x541b}, ret: 0, kvmExitReason: 2},
		{eventType: bpfEventTypeExit, args: [6]uint64{0, kvmRunIOCTL}, ret: 0, kvmExitReason: 2},
	}
	for index, view := range tests {
		result := decorateKVMResult(handler.Result{}, "ioctl", view)
		if result.ReturnDesc != "" {
			t.Fatalf("case %d ReturnDesc = %q, want empty", index, result.ReturnDesc)
		}
	}
}

func TestKVMExitReasonNamesMatchUpstream(t *testing.T) {
	for reason, want := range map[uint32]string{
		0:  "KVM_EXIT_UNKNOWN",
		5:  "KVM_EXIT_HLT",
		39: "KVM_EXIT_MEMORY_FAULT",
		43: "KVM_EXIT_SNP_REQ_CERTS",
		99: "KVM_EXIT_???",
	} {
		if got := kvmExitReasonName(reason); got != want {
			t.Fatalf("reason %d = %q, want %q", reason, got, want)
		}
	}
}

func TestKVMSourceUsesBoundedPendingState(t *testing.T) {
	root := repoRootForTest(t)
	sources := map[string]string{
		"dispatch": readTextFile(t, filepath.Join(root, "bpf/kvm_dispatch.h")),
		"ioctl":    readTextFile(t, filepath.Join(root, "bpf/syscall_ioctl_direct_event_v2.h")),
		"main":     readTextFile(t, filepath.Join(root, "bpf/strace.c")),
	}
	for name, snippets := range map[string][]string{
		"dispatch": {"tracepoint/kvm/kvm_userspace_exit", "CONFIG_KVM_EXIT", "current_pending_task_state", "KVM_RUN_IOCTL", "KVM_EXIT_AUX_VALID"},
		"ioctl":    {"EVENT_FLAG_KVM_EXIT", "KVM_EXIT_AUX_VALID", "body.reserved"},
		"main":     {`#include "kvm_dispatch.h"`},
	} {
		for _, snippet := range snippets {
			if !strings.Contains(sources[name], snippet) {
				t.Fatalf("%s KVM source missing %q", name, snippet)
			}
		}
	}
	for _, forbidden := range []string{"process_vm_readv", "/proc/", "bpf_probe_read_user"} {
		if strings.Contains(sources["dispatch"], forbidden) {
			t.Fatalf("KVM dispatch contains forbidden tracee-memory path %q", forbidden)
		}
	}
}
