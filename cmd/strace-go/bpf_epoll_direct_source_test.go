package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEpollWaitPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	epollDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_epoll_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	for _, snippet := range []string{
		"#define SYS_EPOLL_WAIT 232",
		"#define SYS_EPOLL_PWAIT 281",
		"#define SYS_EPOLL_PWAIT2 441",
		`#include "syscall_epoll_direct_event_v2.h"`,
		"is_epoll_pwait2_direct_syscall(sys_id)",
		"emit_epoll_pwait2_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_epoll_direct_syscall(p->sys_id) && ret_value > 0",
		"emit_epoll_wait_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing epoll wait direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"EPOLL_DIRECT_EVENT_SIZE 12",
		"EPOLL_DIRECT_TIMEOUT_SIZE 16",
		"EPOLL_DIRECT_EVENTS_MAX 504",
		"EPOLL_DIRECT_EVENT_SLOT_MAX 42",
		"is_epoll_direct_syscall(",
		"is_epoll_pwait2_direct_syscall(",
		"capture_epoll_timeout_tlv_direct(",
		"capture_epoll_events_tlv_direct(",
		"emit_epoll_pwait2_enter_event_v2_direct(",
		"emit_epoll_wait_exit_event_v2_direct(",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user(payload_data, EPOLL_DIRECT_TIMEOUT_SIZE",
		"bpf_probe_read_user(&event_data, EPOLL_DIRECT_EVENT_SIZE",
		"bpf_dynptr_write(ptr, data_offset + copied_len, &event_data",
		"init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);",
	} {
		if !strings.Contains(epollDirectHeader, snippet) {
			t.Fatalf("epoll wait direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [epoll_wait, epoll_pwait]",
		"syscalls: [epoll_pwait2]",
		"case 232: /* epoll_wait */",
		"case 281: /* epoll_pwait */",
		"case 441: /* epoll_pwait2 */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("epoll wait syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
