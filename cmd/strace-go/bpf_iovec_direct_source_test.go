package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFIovecPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	// IMPACT: raw syscall program attachment is derived from the typed catalog;
	// scan both the attacher and catalog for the generated wiring contract.
	attachSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_attach.go"))
	catalogSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_program_catalog.go"))
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	iovecCaptureHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_iovec_capture_direct_event_v2.h"))
	iovecDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_iovec_direct_event_v2.h"))
	iovecBaseExitHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_iovec_base_exit_direct_event_v2.h"))

	for _, snippet := range []string{
		"#define SYS_READV 19",
		"#define SYS_WRITEV 20",
		"#define SYS_PROCESS_VM_READV 310",
		"#define SYS_PROCESS_MADVISE 440",
		`#include "syscall_iovec_capture_direct_event_v2.h"`,
		`#include "syscall_iovec_direct_event_v2.h"`,
		`#include "syscall_iovec_base_exit_direct_event_v2.h"`,
		"is_iovec_direct_syscall(sys_id)",
		"emit_iovec_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_iovec_direct_syscall(sys_id) ||",
		"enter_iovec_base",
		"is_iovec_base_enter_direct_syscall(sys_id)",
		"emit_iovec_base_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"exit_iovec_base",
		"is_iovec_base_exit_direct_syscall(p->sys_id)",
		"emit_iovec_base_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) &&
			!strings.Contains(timeDirectHeader, snippet) &&
			!strings.Contains(iovecDirectHeader, snippet) {
			t.Fatalf("BPF source missing iovec direct snippet %q", snippet)
		}
	}
	for _, snippet := range []string{
		"return bpfTailCallProgramEntries(programs, bpfEnterProgramCatalog)",
		"return bpfTailCallProgramEntries(programs, bpfExitProgramCatalog)",
	} {
		if !strings.Contains(attachSource, snippet) {
			t.Fatalf("session source missing process_vm_writev attach snippet %q", snippet)
		}
	}
	for _, snippet := range []string{"\"enter_iovec_base\"", "\"exit_iovec_base\""} {
		if !strings.Contains(catalogSource, snippet) {
			t.Fatalf("program catalog missing process_vm_writev handler %q", snippet)
		}
	}

	for _, snippet := range []string{
		"IOVEC_DIRECT_ELEM_SIZE 16",
		"IOVEC_DIRECT_BYTES_MAX 256",
		"IOVEC_DIRECT_SLOT_MAX 16",
		"IOVEC_BASE_PAYLOAD_SLOT_MAX 7",
		"IOVEC_BASE_PAYLOAD_BYTES_MAX 7",
		"IOVEC_BASE_PAYLOAD_ARG1_BASE 120",
		"IOVEC_BASE_PAYLOAD_CAPACITY",
		"is_iovec_direct_syscall(",
		"is_process_vm_iovec_direct_syscall(",
		"is_iovec_base_enter_direct_syscall(",
		"is_iovec_base_exit_direct_syscall(",
		"capture_iovec_tlv_direct(",
		"capture_iovec_base_payloads_tlv_direct(",
		"PAYLOAD_TLV_KIND_BYTES",
		"iovec_direct_user_len(count)",
		"iovec_direct_copy_len(count)",
		"PAYLOAD_TLV_KIND_IOVEC",
		"EVENT_FLAG_TRUNCATED",
		"record_payload_truncated_event();",
		"bpf_probe_read_user(&iov_data, IOVEC_DIRECT_ELEM_SIZE",
	} {
		if !strings.Contains(iovecCaptureHeader, snippet) {
			t.Fatalf("iovec capture header missing snippet %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_iovec_base_enter_event_v2_direct(",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
	} {
		if !strings.Contains(iovecDirectHeader, snippet) {
			t.Fatalf("iovec direct header missing emitter snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"IOVEC_BASE_EXIT_PAYLOAD_SLOT_MAX 5",
		"IOVEC_BASE_EXIT_PAYLOAD_BYTES_MAX 8",
		"IOVEC_BASE_EXIT_PAYLOAD_CAPACITY",
		"capture_iovec_base_exit_payloads_tlv_direct(",
		"emit_iovec_base_exit_event_v2_direct(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"PAYLOAD_TLV_KIND_BYTES",
		"EVENT_FLAG_TRUNCATED",
	} {
		if !strings.Contains(iovecBaseExitHeader, snippet) {
			t.Fatalf("iovec base exit header missing snippet %q", snippet)
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
