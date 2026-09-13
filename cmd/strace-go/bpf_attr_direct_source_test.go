package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfAttrPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	bpfDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_direct_event_v2.h")) +
		readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h")) +
		readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_capture_direct_event_v2.h")) +
		readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_prog_load_direct_event_v2.h")) +
		readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_kprobe_multi_direct_event_v2.h")) +
		readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_multi_array_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_BPF 321",
		`#include "syscall_bpf_direct_event_v2.h"`,
		"is_bpf_direct_syscall(sys_id)",
		"emit_bpf_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_bpf_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing bpf direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"BPF_DIRECT_ATTR_MAX 512",
		"is_bpf_direct_syscall(",
		"capture_bpf_attr_tlv_direct(",
		"payload_tlv_clamp_u32(requested_len)",
		"payload_tlv_copy_len(requested_len, BPF_DIRECT_ATTR_MAX)",
		"PAYLOAD_TLV_KIND_BYTES",
		"BPF_DIRECT_LICENSE_MAX 64",
		"BPF_DIRECT_INSNS_MAX 64",
		"BPF_DIRECT_LOG_BUF_MAX 256",
		"capture_bpf_prog_load_nested_tlv_direct(",
		"capture_bpf_prog_load_insns_tlv_direct(",
		"BPF_DIRECT_PROG_LOAD_LICENSE_ARG 101",
		"BPF_DIRECT_PROG_LOAD_LOG_BUF_ARG 102",
		"BPF_DIRECT_PROG_LOAD_SIGNATURE_ARG 103",
		"BPF_DIRECT_PROG_LOAD_INSNS_ARG 112",
		"BPF_DIRECT_OBJ_PATHNAME_ARG 104",
		"BPF_DIRECT_RAW_TRACEPOINT_NAME_ARG 105",
		"BPF_DIRECT_BTF_ARG 106",
		"BPF_DIRECT_LINK_ITER_INFO_ARG 107",
		"BPF_DIRECT_KPROBE_MULTI_SYMS_ARG 108",
		"BPF_DIRECT_KPROBE_MULTI_ADDRS_ARG 109",
		"BPF_DIRECT_KPROBE_MULTI_COOKIES_ARG 110",
		"BPF_DIRECT_PROG_STREAM_BUF_ARG 111",
		"BPF_DIRECT_SIGNATURE_MAX 256",
		"BPF_DIRECT_OBJ_PATH_MAX 512",
		"BPF_DIRECT_RAW_TRACEPOINT_NAME_MAX 512",
		"BPF_DIRECT_BTF_MAX 256",
		"BPF_DIRECT_STREAM_BUF_MAX 512",
		"BPF_DIRECT_LINK_ITER_INFO_MAX 20",
		"BPF_DIRECT_KPROBE_MULTI_MAX_ENTRIES 4",
		"BPF_DIRECT_KPROBE_SYM_RECORD_SIZE",
		"PAYLOAD_TLV_KIND_STRING",
		"bpf_probe_read_user_str(payload_data, BPF_DIRECT_LICENSE_MAX",
		"capture_bpf_obj_pathname_tlv_direct(",
		"capture_bpf_raw_tracepoint_name_tlv_direct(",
		"capture_bpf_btf_tlv_direct(",
		"capture_bpf_link_iter_info_tlv_direct(",
		"capture_bpf_kprobe_multi_tlv_direct(",
		"capture_bpf_kprobe_syms_tlv_direct(",
		"capture_bpf_multi_u64_array_tlv_direct(",
		"EVENT_FLAG_TRUNCATED",
		"record_payload_truncated_event();",
		"bpf_probe_read_user(payload_data, copied_len",
		"init_syscall_enter_event_v2_from_ctx(body, ctx, payload_size, 0, -1, -1);",
		"emit_bpf_prog_load_enter_event_v2_direct(",
		"BPF_DIRECT_PROG_LOAD_CAPACITY",
	} {
		if !strings.Contains(bpfDirectHeader, snippet) {
			t.Fatalf("bpf direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [bpf]",
		"case 321: /* bpf */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("bpf still uses old fixed-window rule %q", legacyRule)
		}
	}
}
