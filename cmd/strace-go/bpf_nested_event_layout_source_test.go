package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfNestedCaptureHasDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_capture_direct_event_v2.h"))

	for _, name := range []string{
		"capture_bpf_license_tlv_direct",
		"capture_bpf_bytes_tlv_direct",
		"capture_bpf_string_tlv_direct",
	} {
		signature := "static __always_inline u32 " + name + "("
		if !strings.Contains(capture, signature) {
			t.Fatalf("nested capture module missing primitive %q", name)
		}
		if strings.Contains(nested, signature) {
			t.Fatalf("nested composer must not own primitive %q", name)
		}
	}

	for _, name := range []string{
		"capture_bpf_prog_load_nested_tlv_direct",
		"capture_bpf_obj_pathname_tlv_direct",
		"capture_bpf_raw_tracepoint_name_tlv_direct",
		"capture_bpf_btf_tlv_direct",
		"capture_bpf_prog_stream_read_tlv_direct",
		"capture_bpf_link_iter_info_tlv_direct",
		"capture_bpf_nested_tlv_direct",
	} {
		signature := "static __always_inline u32 " + name + "("
		if !strings.Contains(nested, signature) {
			t.Fatalf("nested composer missing command handler %q", name)
		}
		if strings.Contains(capture, signature) {
			t.Fatalf("nested capture module must not own command handler %q", name)
		}
	}

	if !strings.Contains(nested, `#include "syscall_bpf_nested_capture_direct_event_v2.h"`) {
		t.Fatal("nested composer must include the nested capture module")
	}
	for _, snippet := range []string{
		"bpf_attr_read_u32_direct(",
		"bpf_attr_read_u64_direct(",
		"BPF_DIRECT_NESTED_CAPACITY",
	} {
		if !strings.Contains(nested, snippet) {
			t.Fatalf("nested composer missing shared attribute contract %q", snippet)
		}
	}
	if !strings.Contains(capture, "struct bpf_nested_bytes_capture_request") {
		t.Fatal("nested capture module must use a request object for bytes capture")
	}
}

func TestBPFBpfNestedModulesStayWithinFileLimit(t *testing.T) {
	root := repoRootForTest(t)
	for _, name := range []string{
		"syscall_bpf_nested_direct_event_v2.h",
		"syscall_bpf_nested_capture_direct_event_v2.h",
	} {
		source := readTextFile(t, filepath.Join(root, "bpf", name))
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
