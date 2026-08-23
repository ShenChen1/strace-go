package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfMapGetNextKeyUsesEnterAndExitSnapshots(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	mapExit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_exit_direct_event_v2.h"))
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	enter := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_get_next_key_direct_event_v2.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_MAP_GET_NEXT_KEY 4",
		"BPF_DIRECT_MAP_GET_NEXT_KEY_KEY_IN_ARG 124",
		"BPF_DIRECT_MAP_GET_NEXT_KEY_NEXT_OUT_ARG 125",
		"BPF_DIRECT_MAP_KEY_OFF 8",
		"BPF_DIRECT_MAP_NEXT_KEY_OFF 16",
		"BPF_CORE_READ(map, key_size)",
		"capture_bpf_bytes_tlv_direct(",
		"save_pending_syscall_aux(tid, key_size)",
	} {
		if !strings.Contains(nested+provider+enter, snippet) {
			t.Fatalf("BPF get-next-key enter provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_bpf_map_get_next_key_exit_event_v2_direct(",
		"ret_value != 0",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user(",
		"lookup_pending_syscall_aux0(p->tid)",
		"init_syscall_exit_event_v2_from_pending(",
	} {
		if !strings.Contains(exit+mapExit+provider, snippet) {
			t.Fatalf("BPF get-next-key exit provider missing %q", snippet)
		}
	}
	start := strings.Index(mapExit, "read_bpf_map_get_next_key_output_request_direct(")
	if start < 0 {
		t.Fatal("BPF get-next-key output request is missing")
	}
	end := strings.Index(mapExit[start:], "emit_bpf_map_get_next_key_exit_event_v2_direct(")
	if end < 0 || strings.Contains(mapExit[start:start+end], "lookup_current_bpf_map_direct") {
		t.Fatal("BPF get-next-key exit provider must not re-resolve the map fd")
	}
}
