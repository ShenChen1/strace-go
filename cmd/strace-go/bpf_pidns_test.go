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

func TestNewTraceBPFConfigSnapshotsPIDNamespaceDecoding(t *testing.T) {
	opts := cli.ParseArgs([]string{"--decode-pids=pidns", "/bin/true"})
	config := newTraceBPFConfig(opts)
	opts.DecodePIDsPIDNS = false
	if !config.decodePIDsPIDNS {
		t.Fatal("BPF config lost decode-pids=pidns bootstrap snapshot")
	}
}

func TestPIDNamespaceDecodingSelectsOnlyPIDReturnExitRoutes(t *testing.T) {
	table := map[uint32]meta.Syscall{
		1: {Name: "getpid"},
		2: {Name: "gettid"},
		3: {Name: "fork"},
		4: {Name: "vfork"},
		5: {Name: "getppid"},
		6: {Name: "read"},
	}
	fullPlan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	plain := selectBPFRoutePlan(fullPlan, table, traceBPFConfig{})
	selected := selectBPFRoutePlan(fullPlan, table, traceBPFConfig{decodePIDsPIDNS: true})
	for _, id := range []uint32{1, 2, 3, 4} {
		if selected.exit[id] != exitProgPIDNS {
			t.Fatalf("pid return exit route %d = %d, want %d", id, selected.exit[id], exitProgPIDNS)
		}
	}
	for _, id := range []uint32{5, 6} {
		if selected.exit[id] != plain.exit[id] {
			t.Fatalf("unimplemented pidns exit route %d changed from %d to %d", id, plain.exit[id], selected.exit[id])
		}
	}
}

func TestPIDNamespacePayloadTLVAndReturnComment(t *testing.T) {
	data := make([]byte, pidNamespaceSnapshotSize)
	binary.LittleEndian.PutUint32(data[0:4], 501)
	binary.LittleEndian.PutUint32(data[4:8], 502)
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindPIDNamespace,
		arg:     payloadTLVPIDNamespaceArgIndex,
		flags:   payloadTLVFlagDirectionOut,
		userLen: pidNamespaceSnapshotSize,
		data:    data,
	})
	sections := payloadSectionsForRawPayloadEvent(rawPayloadEvent{
		valid:      true,
		eventType:  bpfEventTypeExit,
		eventFlags: bpfEventFlagPayloadTLV,
		data:       payload,
	})
	if len(sections) != 1 || sections[0].Kind != handler.PayloadKindPIDNamespace {
		t.Fatalf("pidns TLV sections = %+v", sections)
	}
	ctx := &handler.Context{PayloadSections: sections}
	if got := pidNamespaceReturnComment("getpid", 2, ctx); got != " /* 502 in strace's PID NS */" {
		t.Fatalf("getpid comment = %q", got)
	}
	if got := pidNamespaceReturnComment("gettid", 1, ctx); got != " /* 501 in strace's PID NS */" {
		t.Fatalf("gettid comment = %q", got)
	}
	if got := pidNamespaceReturnComment("fork", 2, ctx); got != " /* 502 in strace's PID NS */" {
		t.Fatalf("fork comment = %q", got)
	}
	if got := pidNamespaceReturnComment("vfork", 2, ctx); got != " /* 502 in strace's PID NS */" {
		t.Fatalf("vfork comment = %q", got)
	}
	if got := pidNamespaceReturnComment("getpid", 502, ctx); got != "" {
		t.Fatalf("identity translation comment = %q, want empty", got)
	}
}

func TestPIDNamespaceBPFSourceUsesTracerNamespaceIdentity(t *testing.T) {
	root := repoRootForTest(t)
	sources := map[string]string{
		"runtime":  readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h")),
		"capture":  readTextFile(t, filepath.Join(root, "bpf/syscall_pidns_direct_event_v2.h")),
		"forkHook": readTextFile(t, filepath.Join(root, "bpf/namespace_dispatch.h")),
		"exit":     readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h")),
	}
	for name, snippets := range map[string][]string{
		"runtime":  {"pid_namespace_config_map", "struct pid_namespace_config"},
		"capture":  {"capture_tracer_pid_namespace", "!config->nonce", "read_pid_namespace_number", "PAYLOAD_TLV_KIND_PID_NAMESPACE", "emit_pid_namespace_exit_event_v2_direct"},
		"forkHook": {"capture_pid_namespace_fork_child", "ctx->args[1]"},
		"exit":     {"int exit_pid_namespace(", "emit_pid_namespace_exit_event_v2_direct", "consume_pending_syscall"},
	} {
		for _, snippet := range snippets {
			if !strings.Contains(sources[name], snippet) {
				t.Fatalf("%s pidns source missing %q", name, snippet)
			}
		}
	}
}

func TestPIDNamespaceProgramSelectionIncludesForkSnapshotHook(t *testing.T) {
	table := map[uint32]meta.Syscall{1: {Name: "fork"}}
	fullPlan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	config := traceBPFConfig{decodePIDsPIDNS: true}
	plan := selectBPFRoutePlan(fullPlan, table, config)
	selection, err := newBPFProgramSelection(plan, table, config)
	if err != nil {
		t.Fatalf("pidns selection error = %v", err)
	}
	if !selection.hasProgram(bpfNamespaceForkProgramName) || !selection.hasProgram("exit_pid_namespace") {
		t.Fatalf("pidns selection = %#v, want fork snapshot hook and exit handler", selection.programs)
	}
	if !rawTracepointSpecNames(requiredRawTracepointSpecs(&bpfObjects{}, selection))[bpfNamespaceForkTracepoint] {
		t.Fatal("pidns attachment is missing sched_process_fork raw tracepoint")
	}
}

func TestPIDNamespaceHandshakeNonceUsesNegativePIDRange(t *testing.T) {
	nonce, err := newPIDNamespaceNonce()
	if err != nil {
		t.Fatalf("newPIDNamespaceNonce() error = %v", err)
	}
	if nonce&(1<<31) == 0 {
		t.Fatalf("PID namespace nonce = %#x, want negative pid_t range", nonce)
	}
}

func TestPIDNamespaceDecodingDisablesPlainTextFastPath(t *testing.T) {
	if fastTextPrefixAllowed(traceRenderOptions{decodePIDsPIDNS: true}) {
		t.Fatal("decode-pids=pidns selected plain text fast path")
	}
}
