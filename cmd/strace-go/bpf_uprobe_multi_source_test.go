package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFUprobeMultiDirectSourceContract(t *testing.T) {
	root := repoRootForTest(t)
	runtime := readTextFile(t, filepath.Join(root, "bpf/enter_runtime.h"))
	manifest := readTextFile(t, filepath.Join(root, "bpf/capture_manifest_generated.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	direct := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_uprobe_multi_direct_event_v2.h"))
	for _, snippet := range []string{
		"ENTER_PROG_BPF_UPROBE_MULTI = 51",
	} {
		if !strings.Contains(runtime+manifest, snippet) {
			t.Fatalf("BPF uprobe runtime ABI missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"is_bpf_uprobe_multi_enter_direct(ctx)",
		"bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_UPROBE_MULTI);",
		"int enter_bpf_uprobe_multi(struct trace_event_raw_sys_enter *ctx)",
		"emit_bpf_uprobe_multi_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
	} {
		if !strings.Contains(dispatch, snippet) {
			t.Fatalf("BPF uprobe dispatch missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"BPF_DIRECT_TRACE_UPROBE_MULTI_ATTACH 48",
		"BPF_DIRECT_UPROBE_MULTI_PATH_ARG 133",
		"BPF_DIRECT_UPROBE_MULTI_OFFSETS_ARG 134",
		"BPF_DIRECT_UPROBE_MULTI_REF_CTR_OFFSETS_ARG 135",
		"BPF_DIRECT_UPROBE_MULTI_COOKIES_ARG 136",
		"capture_bpf_uprobe_multi_tlv_direct(",
		"capture_bpf_multi_u64_array_tlv_direct(",
	} {
		if !strings.Contains(nested+provider, snippet) {
			t.Fatalf("BPF uprobe source missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_bpf_uprobe_multi_enter_event_v2_direct(",
		"BPF_DIRECT_UPROBE_MULTI_CAPACITY",
		"capture_bpf_uprobe_multi_tlv_direct(",
	} {
		if !strings.Contains(direct+provider, snippet) {
			t.Fatalf("BPF uprobe emitter missing %q", snippet)
		}
	}
	if strings.Contains(nested, "payload_size += capture_bpf_uprobe_multi_tlv_direct(") {
		t.Fatal("generic BPF nested emitter must not inline uprobe_multi capture")
	}
}
