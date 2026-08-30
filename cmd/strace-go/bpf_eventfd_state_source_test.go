package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEventFDStateUsesEventTimeKernelSnapshot(t *testing.T) {
	root := repoRootForTest(t)
	abi := readTextFile(t, filepath.Join(root, "bpf/event_abi_generated.h"))
	tlv := readTextFile(t, filepath.Join(root, "bpf/payload_tlv.h"))
	fdState := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_state_direct_event_v2.h"))
	runtimeStats := readTextFile(t, filepath.Join(root, "bpf/runtime_stats.h"))

	if !strings.Contains(abi, "EVENTFD_STATE_SNAPSHOT_SIZE 16") {
		t.Fatal("event ABI missing eventfd snapshot size")
	}
	for _, token := range []string{"struct eventfd_state_snapshot"} {
		if !strings.Contains(tlv, token) {
			t.Fatalf("payload_tlv.h missing %q", token)
		}
	}
	for _, token := range []string{
		"capture_eventfd_state_tlv_direct(",
		"BPF_CORE_READ(file, private_data)",
		"BPF_CORE_READ(eventfd, count)",
		"BPF_CORE_READ(eventfd, id)",
		"BPF_CORE_READ(eventfd, flags)",
		"PAYLOAD_TLV_KIND_EVENTFD_STATE",
		"PAYLOAD_TLV_EVENTFD_STATE_ARG_INDEX",
	} {
		if !strings.Contains(fdState, token) {
			t.Fatalf("eventfd state helper missing %q", token)
		}
	}
	for _, token := range []string{"case SYS_READ:", "case SYS_WRITE:"} {
		if !strings.Contains(runtimeStats, token) {
			t.Fatalf("background eventfd state tracking missing %q", token)
		}
	}
}
