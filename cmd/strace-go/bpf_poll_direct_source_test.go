//go:build amd64 && linux

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPollPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	pollDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_poll_direct_event_v2.h"))
	pollCaptureHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_poll_capture_direct_event_v2.h"))
	pollEmitHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_poll_emit_direct_event_v2.h"))
	pollDirectSources := pollDirectHeader + "\n" + pollCaptureHeader + "\n" + pollEmitHeader

	for _, snippet := range []string{
		"#define SYS_POLL 7",
		"#define SYS_PPOLL 271",
		`#include "syscall_poll_direct_event_v2.h"`,
		"is_poll_direct_syscall(sys_id)",
		"emit_poll_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_poll_direct_syscall(p->sys_id) && ret_value > 0",
		"emit_poll_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing poll direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"POLL_DIRECT_FD_SIZE 8",
		"POLL_DIRECT_FDS_MAX 512",
		"POLL_DIRECT_FD_SLOT_MAX 64",
		"POLL_DIRECT_TIMEOUT_SIZE 16",
		"POLL_DIRECT_SIGMASK_SIZE 8",
		"is_poll_direct_syscall(",
		"poll_direct_count(",
		"capture_poll_fds_tlv_direct(",
		"capture_poll_timeout_tlv_direct(",
		"capture_poll_sigmask_tlv_direct(",
		"emit_poll_enter_event_v2_direct(",
		"emit_poll_exit_event_v2_direct(",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user(&fd_data, POLL_DIRECT_FD_SIZE",
		"bpf_probe_read_user(payload_data, POLL_DIRECT_TIMEOUT_SIZE",
		"bpf_probe_read_user(payload_data, POLL_DIRECT_SIGMASK_SIZE",
		"init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);",
	} {
		if !strings.Contains(pollDirectSources, snippet) {
			t.Fatalf("poll direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [poll]",
		"syscalls: [ppoll]",
		"case 7: /* poll */",
		"case 271: /* ppoll */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("poll syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
