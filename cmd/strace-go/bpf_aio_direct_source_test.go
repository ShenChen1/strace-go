package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFAioPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	aioDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_direct_event_v2.h"))
	aioGeteventsDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_aio_getevents_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	captureGenerator := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/gen_bpf_capture.go"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))
	aioDirectSources := aioDirectHeader + aioGeteventsDirectHeader

	for _, snippet := range []string{
		"#define SYS_IO_SETUP 206",
		"#define SYS_IO_GETEVENTS 208",
		"#define SYS_IO_SUBMIT 209",
		"#define SYS_IO_CANCEL 210",
		`#include "syscall_aio_getevents_direct_event_v2.h"`,
		`#include "syscall_aio_direct_event_v2.h"`,
		"is_aio_direct_syscall(sys_id)",
		"emit_aio_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);",
		"is_aio_setup_direct_syscall(p->sys_id) && ret_value >= 0",
		"emit_aio_setup_exit_event_v2_direct(p, ret_value, duration);",
		"is_aio_getevents_direct_syscall(p->sys_id) && ret_value > 0",
		"emit_aio_getevents_exit_event_v2_direct(p, ret_value, duration);",
		"is_aio_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing AIO direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"AIO_SETUP_DIRECT_CTX_SIZE 8",
		"AIO_GETEVENTS_DIRECT_TIMEOUT_SIZE 16",
		"AIO_GETEVENTS_DIRECT_EVENTS_MAX 512",
		"AIO_GETEVENTS_DIRECT_EVENT_SLOT_MAX 16",
		"AIO_SUBMIT_DIRECT_POINTERS_MAX 512",
		"AIO_SUBMIT_DIRECT_POINTER_SLOT_MAX 64",
		"AIO_SUBMIT_DIRECT_IOCB_ARG_BASE 20",
		"AIO_CANCEL_DIRECT_IOCB_SIZE 64",
		"capture_aio_setup_ctx_tlv_direct(",
		"capture_aio_getevents_timeout_tlv_direct(",
		"capture_aio_getevents_events_tlv_direct(",
		"emit_aio_getevents_enter_event_v2_direct(",
		"emit_aio_getevents_exit_event_v2_direct(",
		"capture_aio_submit_pointers_tlv_direct(",
		"capture_aio_submit_iocb_tlv_direct(",
		"emit_aio_submit_enter_event_v2_direct(",
		"capture_aio_cancel_iocb_tlv_direct(",
		"emit_aio_cancel_enter_event_v2_direct(",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user(payload_data, AIO_SETUP_DIRECT_CTX_SIZE",
		"bpf_probe_read_user(&event_data, AIO_GETEVENTS_DIRECT_EVENT_SIZE",
		"bpf_probe_read_user(&iocb_ptr, AIO_SUBMIT_DIRECT_POINTER_SIZE",
		"bpf_dynptr_write(ptr, data_offset + copied_len, &iocb_ptr",
		"bpf_dynptr_write(ptr, data_offset + copied_len, &event_data",
		"bpf_probe_read_user(payload_data, AIO_CANCEL_DIRECT_IOCB_SIZE",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);",
		"init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);",
	} {
		if !strings.Contains(aioDirectSources, snippet) {
			t.Fatalf("AIO direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [io_setup]",
		"case 206: /* io_setup */",
		"syscalls: [io_getevents",
		"case 208: /* io_getevents */",
		"syscalls: [io_submit]",
		"case 209: /* io_submit */",
		"syscalls: [io_cancel]",
		"case 210: /* io_cancel */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("AIO syscall still uses old fixed-window rule %q", legacyRule)
		}
	}

	if strings.Contains(captureGenerator, "ioSubmitExtraCode") {
		t.Fatal("io_submit still has a fixed-window generator special case")
	}
}
