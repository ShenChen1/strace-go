package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// 源码门禁：pending_syscalls 的每次写入失败都必须计入 stats，防止 map 满时静默丢数据。
func TestBPFPendingSaveChecksUpdateResult(t *testing.T) {
	root := repoRootForTest(t)
	headers := map[string]string{
		"bpf/syscall_direct_event_v2.h":         readTextFile(t, filepath.Join(root, "bpf/syscall_direct_event_v2.h")),
		"bpf/syscall_msg_direct_event_v2.h":     readTextFile(t, filepath.Join(root, "bpf/syscall_msg_direct_event_v2.h")),
		"bpf/syscall_network_direct_event_v2.h": readTextFile(t, filepath.Join(root, "bpf/syscall_network_direct_event_v2.h")),
	}
	for name, header := range headers {
		if !strings.Contains(header, "bpf_map_update_elem(&pending_syscalls, &tid, &p, BPF_ANY) != 0") ||
			!strings.Contains(header, "record_pending_update_fail()") {
			t.Fatalf("%s does not check pending_syscalls update result and record failure", name)
		}
	}
}

func TestBPFStatsHasPendingUpdateFailCounter(t *testing.T) {
	src := loadBPFSources(t)
	if !strings.Contains(src.straceSource, "u64 pending_update_fail;") {
		t.Fatal("bpf/strace.c bpf_stats missing pending_update_fail counter")
	}
	if !strings.Contains(src.straceSource, "static __always_inline void record_pending_update_fail(void)") {
		t.Fatal("bpf/strace.c missing record_pending_update_fail helper")
	}
}
