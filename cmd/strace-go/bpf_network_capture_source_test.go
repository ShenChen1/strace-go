package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFNetworkCaptureHasDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	captureHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_network_capture_direct_event_v2.h"))
	networkHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_network_direct_event_v2.h"))

	for _, snippet := range []string{
		"struct network_tlv_capture_request",
		"struct network_socklen_capture_request",
		"NETWORK_DIRECT_BYTES_MAX 512",
		"NETWORK_DIRECT_SOCKADDR_MAX 128",
		"NETWORK_DIRECT_SOCKLEN_SIZE 4",
		"network_direct_sockopt_payload_len(",
		"network_direct_read_socklen(",
		"capture_network_tlv_direct(",
		"capture_network_socklen_tlv_direct(",
		"bpf_probe_read_user(",
		"payload_tlv_write_header_direct(",
	} {
		if !strings.Contains(captureHeader, snippet) {
			t.Fatalf("network capture header missing snippet %q", snippet)
		}
	}

	if !strings.Contains(networkHeader, `#include "syscall_network_capture_direct_event_v2.h"`) {
		t.Fatal("network facade should include the dedicated capture header")
	}
	for _, definition := range []string{
		"static __always_inline u32 network_direct_sockopt_payload_len(",
		"static __always_inline int network_direct_read_socklen(",
	} {
		if strings.Contains(networkHeader, definition) {
			t.Fatalf("network facade still owns capture definition %q", definition)
		}
	}
	for _, signature := range []string{
		"static __always_inline u32 capture_network_tlv_direct(\n    struct network_tlv_capture_request *request)",
		"static __always_inline u32 capture_network_socklen_tlv_direct(\n    struct network_socklen_capture_request *request)",
	} {
		if !strings.Contains(captureHeader, signature) {
			t.Fatalf("network capture API is not request-based: %q", signature)
		}
	}
	for _, forbidden := range []string{
		"save_pending_network_syscall_args(",
		"emit_network_enter_event_v2_direct(",
	} {
		if strings.Contains(captureHeader, forbidden) {
			t.Fatalf("network capture header must not own state/emitter symbol %q", forbidden)
		}
	}

	if strings.Count(networkHeader, "\n") > 500 || strings.Count(captureHeader, "\n") > 500 {
		t.Fatal("network capture modules exceed the 500-line source limit")
	}
}
