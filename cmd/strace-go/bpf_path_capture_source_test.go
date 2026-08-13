package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPathCaptureHasDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	captureHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_path_capture_direct_event_v2.h"))
	pathHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_path_direct_event_v2.h"))

	for _, snippet := range []string{
		"PATH_ONLY_DIRECT_PATH_MAX 4096",
		"PATH_ONLY_DIRECT_FIRST_CHUNK 2048",
		"PATH_ONLY_DIRECT_SECOND_CHUNK 2049",
		"DUAL_PATH_DIRECT_PATH_MAX 512",
		"capture_path_only_tlv_direct(",
		"capture_dual_path_tlv_direct(",
		"bpf_probe_read_user_str(",
		"payload_tlv_write_header_direct(",
	} {
		if !strings.Contains(captureHeader, snippet) {
			t.Fatalf("path capture header missing snippet %q", snippet)
		}
	}

	if !strings.Contains(pathHeader, `#include "syscall_path_capture_direct_event_v2.h"`) {
		t.Fatal("path facade should include the dedicated capture header")
	}
	for _, definition := range []string{
		"static __always_inline u32 capture_path_only_tlv_direct(",
		"static __always_inline u32 capture_dual_path_tlv_direct(",
	} {
		if strings.Contains(pathHeader, definition) {
			t.Fatalf("path facade still owns capture definition %q", definition)
		}
	}
	if strings.Contains(captureHeader, "emit_path_only_enter_event_v2_direct(") ||
		strings.Contains(captureHeader, "emit_dual_path_enter_event_v2_direct(") {
		t.Fatal("path capture header must not own path event emitters")
	}

	if strings.Count(pathHeader, "\n") > 500 || strings.Count(captureHeader, "\n") > 500 {
		t.Fatal("path capture modules exceed the 500-line source limit")
	}
}
