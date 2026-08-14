package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMmsgCaptureSplitsStructAndBytesOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_mmsg_capture_direct_event_v2.h")
	structCapture := read("syscall_mmsg_struct_capture_direct_event_v2.h")
	bytesCapture := read("syscall_mmsg_bytes_capture_direct_event_v2.h")
	core := read("syscall_msg_core_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_mmsg_struct_capture_direct_event_v2.h"`,
		`#include "syscall_mmsg_bytes_capture_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("mmsg capture facade missing %q", include)
		}
	}

	for _, snippet := range []string{
		"capture_mmsghdr_tlv_direct(",
		"capture_mmsg_timespec_tlv_direct(",
		"capture_mmsg_iovec_tlv_direct(",
		"capture_mmsg_enter_payloads_tlv_direct(",
		"capture_mmsg_exit_payloads_tlv_direct(",
	} {
		if !strings.Contains(structCapture, snippet) {
			t.Fatalf("mmsg struct capture missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_mmsg_bytes_base_slot_enter_payloads_tlv_direct(",
		"capture_mmsg_bytes_base0_enter_payloads_tlv_direct(",
		"capture_recvmmsg_base_slot_exit_payloads_tlv_direct(",
		"capture_recvmmsg_base0_exit_payloads_tlv_direct(",
	} {
		if !strings.Contains(bytesCapture, snippet) {
			t.Fatalf("mmsg bytes capture missing %q", snippet)
		}
	}
	if strings.Contains(structCapture, "capture_mmsg_bytes_base_slot_enter_payloads_tlv_direct(") {
		t.Fatal("mmsg struct capture owns bytes capture")
	}
	if strings.Contains(bytesCapture, "capture_mmsghdr_tlv_direct(") {
		t.Fatal("mmsg bytes capture owns aggregate struct capture")
	}
	if !strings.Contains(core, "mmsg_iovec_arg_index_for_slot(") {
		t.Fatal("mmsg core must own synthetic iovec argument policy")
	}
	for _, source := range map[string]string{
		"facade": facade, "struct": structCapture, "bytes": bytesCapture,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("mmsg %s capture lines = %d, want <= 500", source, lines)
		}
	}
}
