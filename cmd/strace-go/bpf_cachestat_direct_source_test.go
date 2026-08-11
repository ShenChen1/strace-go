package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFCachestatPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	cachestatDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_cachestat_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_CACHESTAT 451",
		`#include "syscall_cachestat_direct_event_v2.h"`,
		"sys_id == SYS_CACHESTAT",
		"emit_cachestat_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);",
		"is_cachestat_direct_syscall(sys_id)",
		"is_cachestat_direct_syscall(p->sys_id) && ret_value >= 0",
		"emit_cachestat_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing cachestat direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"CACHESTAT_DIRECT_RANGE_SIZE 16",
		"CACHESTAT_DIRECT_STATS_SIZE 40",
		"capture_cachestat_struct_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"scratch->args[1]",
		"p->args[2]",
		"emit_cachestat_enter_event_v2_direct(",
		"emit_cachestat_exit_event_v2_direct(",
		"init_syscall_enter_event_v2_from_args(&body, scratch->args, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(cachestatDirectHeader, snippet) {
			t.Fatalf("cachestat direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [cachestat]",
		"case 451: /* cachestat */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("cachestat still uses old fixed-window rule %q", legacyRule)
		}
	}
}
