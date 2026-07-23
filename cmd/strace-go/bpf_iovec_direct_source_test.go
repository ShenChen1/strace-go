package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFIovecPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	iovecDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_iovec_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_READV 19",
		"#define SYS_WRITEV 20",
		"#define SYS_PROCESS_VM_READV 310",
		"#define SYS_PROCESS_MADVISE 440",
		`#include "syscall_iovec_direct_event_v2.h"`,
		"is_iovec_direct_syscall(sys_id)",
		"emit_iovec_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_iovec_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing iovec direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"IOVEC_DIRECT_ELEM_SIZE 16",
		"IOVEC_DIRECT_BYTES_MAX 256",
		"IOVEC_DIRECT_SLOT_MAX 16",
		"is_iovec_direct_syscall(",
		"is_process_vm_iovec_direct_syscall(",
		"capture_iovec_tlv_direct(",
		"iovec_direct_user_len(count)",
		"iovec_direct_copy_len(count)",
		"PAYLOAD_TLV_KIND_IOVEC",
		"EVENT_FLAG_TRUNCATED",
		"record_payload_truncated_event();",
		"bpf_probe_read_user(&iov_data, IOVEC_DIRECT_ELEM_SIZE",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(iovecDirectHeader, snippet) {
			t.Fatalf("iovec direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [readv, writev, preadv, pwritev, preadv2, pwritev2, vmsplice]",
		"syscalls: [process_vm_readv, process_vm_writev]",
		"syscalls: [process_madvise]",
		"case 19: /* readv */",
		"case 20: /* writev */",
		"case 278: /* vmsplice */",
		"case 295: /* preadv */",
		"case 296: /* pwritev */",
		"case 310: /* process_vm_readv */",
		"case 311: /* process_vm_writev */",
		"case 327: /* preadv2 */",
		"case 328: /* pwritev2 */",
		"case 440: /* process_madvise */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("iovec syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
