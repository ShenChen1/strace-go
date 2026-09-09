package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFOpenat2PayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	openat2DirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_openat2_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_OPENAT2 437",
		`#include "syscall_openat2_direct_event_v2.h"`,
		"is_openat2_direct_syscall(sys_id)",
		"emit_openat2_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);",
		"is_openat2_direct_syscall(sys_id) ||",
		"emit_openat2_exit_event_v2_direct(p, ret_value, duration);",
		"is_openat2_direct_syscall(p->sys_id)",
	} {
		if !strings.Contains(straceSource, snippet) &&
			!strings.Contains(timeDirectHeader, snippet) &&
			!strings.Contains(openat2DirectHeader, snippet) {
			t.Fatalf("BPF source missing openat2 direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"OPENAT2_DIRECT_PATH_MAX 4096",
		"OPENAT2_DIRECT_HOW_MIN 24",
		"OPENAT2_DIRECT_HOW_MAX 64",
		"OPENAT2_DIRECT_EXIT_PAYLOAD_CAPACITY",
		"capture_openat2_path_tlv_direct(",
		"capture_openat2_how_tlv_direct(",
		"capture_fd_state_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRING",
		"PAYLOAD_TLV_KIND_STRUCT",
		"bpf_probe_read_user_str(payload_data, OPENAT2_DIRECT_PATH_MAX",
		"bpf_probe_read_user(payload_data, OPENAT2_DIRECT_HOW_MIN",
		"bpf_probe_read_user(\n                (void *)((char *)payload_data + OPENAT2_DIRECT_HOW_MIN",
		"emit_openat2_exit_event_v2_direct(",
		"init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);",
	} {
		if !strings.Contains(openat2DirectHeader, snippet) {
			t.Fatalf("openat2 direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [openat2]",
		"case 437: /* openat2 */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("openat2 still uses old fixed-window rule %q", legacyRule)
		}
	}
}

func TestBPFOpenat2CapturesConfiguredDfdPath(t *testing.T) {
	root := repoRootForTest(t)
	openat2DirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_openat2_direct_event_v2.h"))
	enterDispatch := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))

	for _, snippet := range []string{
		"FD_PATH_DIRECT_SECTION_MAX",
		"CONFIG_FD_STATE",
		"capture_fd_path_tlv_direct(",
		"payload_capacity = fd_path_capacity + OPENAT2_DIRECT_PAYLOAD_CAPACITY",
		"emit_openat2_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);",
	} {
		if !strings.Contains(openat2DirectHeader, snippet) && !strings.Contains(enterDispatch, snippet) {
			t.Fatalf("openat2 direct path capture missing snippet %q", snippet)
		}
	}
}
