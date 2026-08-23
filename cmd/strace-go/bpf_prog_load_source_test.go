package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFProgLoadUsesDedicatedEnterProvider(t *testing.T) {
	root := repoRootForTest(t)
	runtime := readTextFile(t, filepath.Join(root, "bpf/enter_runtime.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	direct := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_prog_load_direct_event_v2.h"))

	for _, snippet := range []string{
		"ENTER_PROG_BPF_PROG_LOAD = 52",
		"ENTER_PROG_BPF_PROG_LOAD_DEBUG = 53",
	} {
		if !strings.Contains(runtime, snippet) {
			t.Fatalf("BPF prog_load runtime ABI missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"is_bpf_prog_load_enter_direct(ctx)",
		"bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_PROG_LOAD);",
		"int enter_bpf_prog_load(struct trace_event_raw_sys_enter *ctx)",
		"emit_bpf_prog_load_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_PROG_LOAD_DEBUG);",
		"int enter_bpf_prog_load_debug(struct trace_event_raw_sys_enter *ctx)",
		"emit_bpf_prog_load_debug_enter_fragment_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
	} {
		if !strings.Contains(dispatch, snippet) {
			t.Fatalf("BPF prog_load dispatch missing %q", snippet)
		}
	}
	progLoadTailCall := strings.Index(dispatch, "bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_PROG_LOAD);")
	uprobeDecision := strings.Index(dispatch, "int is_uprobe_multi = is_bpf_uprobe_multi_enter_direct(ctx);")
	if progLoadTailCall < 0 || uprobeDecision < 0 || uprobeDecision > progLoadTailCall {
		t.Fatal("BPF dynamic provider decisions must be cached before the first tail call")
	}
	for _, snippet := range []string{
		"BPF_DIRECT_PROG_LOAD_CAPACITY",
		"BPF_DIRECT_PROG_LOAD_BASE_CAPACITY",
		"BPF_DIRECT_PROG_LOAD_DEBUG_CAPACITY",
		"4 * PAYLOAD_TLV_HEADER_SIZE",
		"is_bpf_prog_load_enter_direct(",
		"capture_bpf_prog_load_insns_tlv_direct(",
		"capture_bpf_prog_load_nested_tlv_direct(",
		"capture_bpf_prog_load_fd_array_tlv_direct(",
		"capture_bpf_prog_load_func_info_tlv_direct(",
		"capture_bpf_prog_load_line_info_tlv_direct(",
		"capture_bpf_prog_load_core_relos_tlv_direct(",
		"capture_bpf_prog_load_debug_nested_tlv_direct(",
	} {
		if !strings.Contains(provider, snippet) {
			t.Fatalf("BPF prog_load provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_bpf_prog_load_enter_event_v2_direct(",
		"emit_bpf_prog_load_debug_enter_fragment_event_v2_direct(",
		"BPF_DIRECT_PROG_LOAD_BASE_CAPACITY",
		"BPF_DIRECT_PROG_LOAD_DEBUG_CAPACITY",
		"capture_bpf_prog_load_nested_tlv_direct(",
		"capture_bpf_prog_load_debug_nested_tlv_direct(",
	} {
		if !strings.Contains(direct, snippet) {
			t.Fatalf("BPF prog_load emitter missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"BPF_DIRECT_PROG_LOAD_LINE_INFO_ARG 143",
		"BPF_DIRECT_PROG_LOAD_CORE_RELOS_ARG 144",
		"BPF_DIRECT_PROG_LOAD_LINE_INFO_MAX",
		"BPF_DIRECT_PROG_LOAD_CORE_RELOS_MAX",
	} {
		if !strings.Contains(nested, snippet) {
			t.Fatalf("BPF prog_load nested ABI missing %q", snippet)
		}
	}

	composerStart := strings.Index(nested, "static __always_inline u32 capture_bpf_nested_tlv_direct(")
	if composerStart < 0 {
		t.Fatal("generic BPF nested composer is missing")
	}
	if strings.Contains(nested[composerStart:], "capture_bpf_prog_load_nested_tlv_direct(") {
		t.Fatal("generic BPF nested composer must not inline prog_load capture")
	}

	capacityStart := strings.Index(nested, "#define BPF_DIRECT_NESTED_CAPACITY")
	if capacityStart < 0 {
		t.Fatal("generic BPF nested capacity definition is missing")
	}
	capacityEnd := strings.Index(nested[capacityStart:], "static __always_inline int bpf_attr_read_u32_direct(")
	if capacityEnd < 0 {
		t.Fatal("generic BPF nested capacity boundary is missing")
	}
	capacity := nested[capacityStart : capacityStart+capacityEnd]
	for _, snippet := range []string{
		"BPF_DIRECT_LICENSE_MAX",
		"BPF_DIRECT_INSNS_MAX",
		"BPF_DIRECT_LOG_BUF_MAX",
		"BPF_DIRECT_SIGNATURE_MAX",
		"BPF_DIRECT_PROG_LOAD_FD_ARRAY_MAX",
		"BPF_DIRECT_PROG_LOAD_FUNC_INFO_MAX",
	} {
		if strings.Contains(capacity, snippet) {
			t.Fatalf("generic BPF capacity still reserves prog_load-only buffer %q", snippet)
		}
	}

	emitterStart := strings.Index(direct, "static __noinline void emit_bpf_enter_event_v2_direct(")
	progLoadEmitterStart := strings.Index(direct, "static __noinline void emit_bpf_prog_load_enter_event_v2_direct(")
	if emitterStart < 0 || progLoadEmitterStart < 0 || progLoadEmitterStart <= emitterStart {
		t.Fatal("BPF prog_load emitter must follow the generic emitter")
	}
	if strings.Contains(direct[emitterStart:progLoadEmitterStart], "capture_bpf_prog_load_nested_tlv_direct(") {
		t.Fatal("generic BPF emitter must not inline prog_load capture")
	}

	baseStart := strings.Index(provider, "static __noinline u32 capture_bpf_prog_load_nested_tlv_direct(")
	debugStart := strings.Index(provider, "static __noinline u32 capture_bpf_prog_load_debug_nested_tlv_direct(")
	if baseStart < 0 || debugStart <= baseStart {
		t.Fatal("BPF prog_load base/debug composers are not ordered")
	}
	baseComposer := provider[baseStart:debugStart]
	for _, name := range []string{
		"capture_bpf_prog_load_fd_array_tlv_direct(",
		"capture_bpf_prog_load_func_info_tlv_direct(",
		"capture_bpf_prog_load_line_info_tlv_direct(",
		"capture_bpf_prog_load_core_relos_tlv_direct(",
	} {
		if strings.Contains(baseComposer, name) {
			t.Fatalf("base prog_load composer still owns debug-only nested capture %q", name)
		}
	}
	for _, name := range []string{
		"capture_bpf_prog_load_fd_array_tlv_direct(",
		"capture_bpf_prog_load_func_info_tlv_direct(",
		"capture_bpf_prog_load_line_info_tlv_direct(",
		"capture_bpf_prog_load_core_relos_tlv_direct(",
	} {
		if !strings.Contains(provider[debugStart:], name) {
			t.Fatalf("debug prog_load composer does not own %s", name)
		}
	}
}
