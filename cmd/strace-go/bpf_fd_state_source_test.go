package main

import (
	"strings"
	"testing"
)

func TestBPFFDStateUsesEventTimeCoreSnapshot(t *testing.T) {
	src := loadBPFSources(t)
	wantTLV := []string{
		"PAYLOAD_TLV_KIND_FD_STATE",
		"PAYLOAD_TLV_FD_STATE_ARG_INDEX 0xffff",
		"struct fd_state_snapshot",
		"FD_STATE_SNAPSHOT_SIZE 48",
	}
	for _, token := range wantTLV {
		if !strings.Contains(src.tlvHeader, token) {
			t.Fatalf("payload_tlv.h missing %q", token)
		}
	}
	wantCapture := []string{
		"capture_fd_state_tlv_direct(",
		"bpf_get_current_task()",
		"BPF_CORE_READ(task, files)",
		"BPF_CORE_READ(files, fdt)",
		"BPF_CORE_READ(fdt, max_fds)",
		"BPF_CORE_READ(file, f_inode)",
		"BPF_CORE_READ(inode, i_mode)",
		"BPF_CORE_READ(inode, i_ino)",
		"BPF_CORE_READ(file, f_pos)",
		"emit_fd_state_exit_event_v2_direct(",
	}
	for _, token := range wantCapture {
		if !strings.Contains(src.fdStateHeader, token) {
			t.Fatalf("fd state helper missing %q", token)
		}
	}
	for _, token := range []string{"SYS_DUP", "SYS_DUP2", "SYS_DUP3", "SYS_EVENTFD", "SYS_EVENTFD2", "SYS_EPOLL_CREATE", "SYS_EPOLL_CREATE1", "SYS_TIMERFD_CREATE", "SYS_INOTIFY_INIT", "SYS_INOTIFY_INIT1", "SYS_SIGNALFD", "SYS_SIGNALFD4"} {
		if !strings.Contains(src.fdStateHeader, token) {
			t.Fatalf("fd state helper missing duplicated-fd syscall %q", token)
		}
	}
	for _, token := range []string{
		"FD_ARRAY_DIRECT_FD_STATE_COUNT 2",
		"read_fd_array_values_direct(",
		"capture_fd_state_array_tlvs_direct(",
		"capture_fd_state_tlv_direct(",
	} {
		if !strings.Contains(src.fdArrayDirectHeader, token) {
			t.Fatalf("fd array state helper missing %q", token)
		}
	}
	for _, token := range []string{"case SYS_PIPE:", "case SYS_PIPE2:", "case SYS_SOCKETPAIR:"} {
		if !strings.Contains(src.straceSource, token) {
			t.Fatalf("runtime fd state tracking missing array syscall %q", token)
		}
	}
	wantDispatch := []string{
		`#include "syscall_fd_state_direct_event_v2.h"`,
		"is_fd_state_exit_direct_syscall(p->sys_id)",
		"ret_value >= 0",
		"emit_fd_state_exit_event_v2_direct(p, ret_value, duration);",
	}
	for _, token := range wantDispatch {
		if !strings.Contains(src.straceSource, token) {
			t.Fatalf("BPF dispatch missing %q", token)
		}
	}
}
