package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMmsgBytesEnterEmittersHaveDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	enter := readTextFile(t, filepath.Join(root, "bpf/syscall_msg_enter_direct_event_v2.h"))
	bytes := readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_bytes_enter_direct_event_v2.h"))
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_msg_direct_event_v2.h"))

	for _, name := range []string{
		"emit_mmsg_bytes_base0_enter_event_v2_direct",
		"emit_mmsg_bytes_base1_enter_event_v2_direct",
		"emit_mmsg_bytes_base2_enter_event_v2_direct",
		"emit_mmsg_bytes_base3_enter_event_v2_direct",
	} {
		signature := "static __always_inline void " + name + "("
		if !strings.Contains(bytes, signature) {
			t.Fatalf("mmsg bytes module missing emitter %q", name)
		}
		if strings.Contains(enter, signature) {
			t.Fatalf("msg enter module must not own emitter %q", name)
		}
	}

	if !strings.Contains(facade, `#include "syscall_mmsg_bytes_enter_direct_event_v2.h"`) {
		t.Fatal("msg facade must include the mmsg bytes enter module")
	}
	for _, snippet := range []string{
		"MSG_DIRECT_MMSG_BYTES_ENTER_MAX",
		"capture_mmsg_bytes_base0_enter_payloads_tlv_direct(",
		"capture_mmsg_bytes_base3_enter_payloads_tlv_direct(",
		"bpf_ringbuf_submit_dynptr(&ptr, 0);",
	} {
		if !strings.Contains(bytes, snippet) {
			t.Fatalf("mmsg bytes module missing %q", snippet)
		}
	}
}
