package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFCapabilityPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	capabilityDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_capability_direct_event_v2.h"))
	sessionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session.go"))

	for _, snippet := range []string{
		"volatile const u32 SYS_CAPGET = 125;",
		"volatile const u32 SYS_CAPSET = 126;",
		`#include "syscall_capability_direct_event_v2.h"`,
		"is_capability_direct_syscall(sys_id)",
		"emit_capability_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"p->sys_id == SYS_CAPGET && ret_value >= 0",
		"emit_capability_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing capability direct snippet %q", snippet)
		}
	}
	if !strings.Contains(sessionSource, `setVar("SYS_CAPGET", getSysID("capget", 125))`) ||
		!strings.Contains(sessionSource, `setVar("SYS_CAPSET", getSysID("capset", 126))`) {
		t.Fatal("BPF loader should set capability syscall ids")
	}

	for _, snippet := range []string{
		"CAPABILITY_DIRECT_HEADER_SIZE 8",
		"CAPABILITY_DIRECT_WORD_SIZE 12",
		"CAPABILITY_DIRECT_DATA_SIZE 24",
		"CAPABILITY_VERSION_1",
		"capability_direct_data_size(",
		"capture_capability_header_tlv_direct(",
		"capture_capability_struct_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, probe_ret_enter, -1);",
	} {
		if !strings.Contains(capabilityDirectHeader, snippet) {
			t.Fatalf("capability direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [capget]",
		"syscalls: [capset]",
		"case 125: /* capget */",
		"case 126: /* capset */",
		"capture_capset_data(",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) || strings.Contains(straceSource, legacyRule) {
			t.Fatalf("capability still uses old fixed-window rule %q", legacyRule)
		}
	}
}
