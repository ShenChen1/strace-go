package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFQuotaPayloadUsesDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	quotaHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_quota_direct_event_v2.h"))
	xfsHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_quota_xfs_direct_event_v2.h"))
	quotaDispatch := readTextFile(t, filepath.Join(root, "bpf/quota_dispatch.h"))

	for _, snippet := range []string{
		"#define SYS_QUOTACTL 179",
		"#define SYS_QUOTACTL_FD 443",
		`#include "syscall_quota_direct_event_v2.h"`,
		`#include "syscall_quota_xfs_direct_event_v2.h"`,
		`#include "quota_dispatch.h"`,
		"ENTER_PROG_QUOTA = 44",
		"EXIT_PROG_QUOTA = 6",
		"is_quota_direct_syscall(sys_id)",
	} {
		if !strings.Contains(straceSource, snippet) {
			t.Errorf("BPF source missing quota direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"QUOTA_XFS_DISK_SIZE 112",
		"QUOTA_XFS_STAT_SIZE 80",
		"QUOTA_XFS_STATV_SIZE 160",
		"capture_quota_xfs_struct_tlv_direct(",
		"quota_xfs_enter_struct_size(",
		"quota_xfs_exit_struct_size(",
	} {
		if !strings.Contains(xfsHeader, snippet) {
			t.Errorf("quota XFS header missing snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"QUOTA_DIRECT_DQBLK_SIZE 72",
		"QUOTA_DIRECT_DQINFO_SIZE 24",
		"QUOTA_DIRECT_FORMAT_SIZE 4",
		"capture_quota_struct_tlv_direct(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"emit_quota_enter_event_v2_direct(",
		"emit_quota_exit_event_v2_direct(",
	} {
		if !strings.Contains(quotaHeader, snippet) {
			t.Errorf("quota direct header missing snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"SEC(\"tracepoint/raw_syscalls/sys_enter\")\nint enter_quota",
		"SEC(\"tracepoint/raw_syscalls/sys_exit\")\nint exit_quota",
		"is_quota_direct_syscall(p->sys_id)",
	} {
		if !strings.Contains(quotaDispatch, snippet) {
			t.Errorf("quota dispatch header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [quotactl]",
		"syscalls: [quotactl_fd]",
		"case 179: /* quotactl */",
		"case 443: /* quotactl_fd */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Errorf("quota still uses old fixed-window rule %q", legacyRule)
		}
	}
}
