package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFTracingMultiDirectSourceContract(t *testing.T) {
	root := repoRootForTest(t)
	runtime := readTextFile(t, filepath.Join(root, "bpf/enter_runtime.h"))
	manifest := readTextFile(t, filepath.Join(root, "bpf/capture_manifest_generated.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	direct := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_tracing_multi_direct_event_v2.h"))
	multiArray := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_multi_array_direct_event_v2.h"))

	for _, snippet := range []string{
		"ENTER_PROG_BPF_TRACING_MULTI = 54",
	} {
		if !strings.Contains(runtime+manifest, snippet) {
			t.Fatalf("BPF tracing_multi runtime ABI missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"is_bpf_tracing_multi_enter_direct(ctx)",
		"bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_TRACING_MULTI);",
		"int enter_bpf_tracing_multi(struct trace_event_raw_sys_enter *ctx)",
		"emit_bpf_tracing_multi_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
	} {
		if !strings.Contains(dispatch, snippet) {
			t.Fatalf("BPF tracing_multi dispatch missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __noinline int is_bpf_tracing_multi_enter_direct(",
		"BPF_DIRECT_TRACE_FENTRY_MULTI_ATTACH 59",
		"BPF_DIRECT_TRACE_FEXIT_MULTI_ATTACH 60",
		"BPF_DIRECT_TRACE_FSESSION_MULTI_ATTACH 61",
		"BPF_DIRECT_TRACING_MULTI_IDS_ARG 145",
		"BPF_DIRECT_TRACING_MULTI_COOKIES_ARG 146",
		"capture_bpf_multi_u32_array_tlv_direct(",
		"capture_bpf_tracing_multi_tlv_direct(",
	} {
		if !strings.Contains(nested+provider+multiArray, snippet) {
			t.Fatalf("BPF tracing_multi source missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"syscall_bpf_tracing_multi_direct_event_v2.h",
		"emit_bpf_tracing_multi_enter_event_v2_direct(",
		"BPF_DIRECT_TRACING_MULTI_CAPACITY",
	} {
		if !strings.Contains(direct+provider, snippet) {
			t.Fatalf("BPF tracing_multi emitter missing %q", snippet)
		}
	}
	if strings.Contains(nested, "payload_size += capture_bpf_tracing_multi_tlv_direct(") {
		t.Fatal("generic BPF nested emitter must not inline tracing_multi capture")
	}
}
