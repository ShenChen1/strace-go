package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestBPFBasicPayloadsUseTLVFlag(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	tlvHeader := readTextFile(t, filepath.Join(root, "bpf/payload_tlv.h"))
	directHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_direct_event_v2.h"))

	if !strings.Contains(straceSource, `#include "payload_tlv.h"`) {
		t.Fatal("strace.c does not include payload_tlv.h")
	}
	if !strings.Contains(straceSource, "#define SYS_READ 0") {
		t.Fatal("strace.c missing SYS_READ constant for read TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_CLOSE 3") {
		t.Fatal("strace.c missing SYS_CLOSE constant for scalar direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_PREAD64 17") {
		t.Fatal("strace.c missing SYS_PREAD64 constant for pread64 TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_PWRITE64 18") {
		t.Fatal("strace.c missing SYS_PWRITE64 constant for pwrite64 TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_GETPID 39") {
		t.Fatal("strace.c missing SYS_GETPID constant for scalar direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_OPENAT 257") {
		t.Fatal("strace.c missing SYS_OPENAT constant for openat TLV capture")
	}
	if !strings.Contains(straceSource, `#include "syscall_direct_event_v2.h"`) {
		t.Fatal("strace.c should include scalar direct event v2 helpers")
	}
	if !strings.Contains(straceSource, "#define EVENT_V2_ENTER_BODY_LEN 72") ||
		!strings.Contains(straceSource, "s64 ret;") ||
		!strings.Contains(straceSource, "s32 probe_ret_enter;") ||
		!strings.Contains(straceSource, "body->ret = e->ret;") ||
		!strings.Contains(directHeader, "body->probe_ret_enter = probe_ret_enter;") {
		t.Fatal("event v2 enter body should carry ret and probe status for exec-style enter states")
	}
	if strings.Contains(straceSource, "capture_openat_tlv(e);") || strings.Contains(tlvHeader, "capture_openat_tlv") {
		t.Fatal("openat TLV capture should not use the bpf_event fixed-window helper")
	}
	if strings.Contains(straceSource, "capture_write_tlv(e);") || strings.Contains(tlvHeader, "capture_write_tlv") {
		t.Fatal("write TLV capture should not use the bpf_event fixed-window helper")
	}
	if strings.Contains(straceSource, "capture_read_tlv(e);") || strings.Contains(tlvHeader, "capture_read_tlv") {
		t.Fatal("read TLV capture should not use the bpf_event fixed-window helper")
	}
	if calls := strings.Count(straceSource, "capture_exec_tlv(e, 0, 1, 2);"); calls != 2 {
		t.Fatalf("execve capture_exec_tlv calls = %d, want enter and failed-exit paths", calls)
	}
	if calls := strings.Count(straceSource, "capture_exec_tlv(e, 1, 2, 3);"); calls != 2 {
		t.Fatalf("execveat capture_exec_tlv calls = %d, want enter and failed-exit paths", calls)
	}
	if !strings.Contains(straceSource, "PAYLOAD_TLV_HEADER_SIZE + sizeof(*snapshot)") {
		t.Fatal("exec TLV capture should append filename section after exec args snapshot")
	}
	if !strings.Contains(straceSource, "saved_flags | EVENT_FLAG_GENERIC_ENTER") {
		t.Fatal("generic enter flag should preserve payload TLV flag")
	}
	if !strings.Contains(straceSource, "header->event_type = EVENT_TYPE_LIFECYCLE;") ||
		!strings.Contains(straceSource, "body->action = kind;") {
		t.Fatal("lifecycle events should build event v2 fields without the bpf_event carrier")
	}
	if strings.Contains(straceSource, "lifecycle_action") {
		t.Fatal("bpf_event carrier should not retain lifecycle_action")
	}
	if strings.Contains(straceSource, "e->ptr") {
		t.Fatal("bpf_event carrier should not retain raw pointer field")
	}
	if !strings.Contains(straceSource, "e->event_type == EVENT_TYPE_ENTER || e->event_type == EVENT_TYPE_EXIT") {
		t.Fatal("truncated stats should ignore lifecycle action ids sharing event_flags")
	}
	if !strings.Contains(straceSource, "emit_syscall_event_v2(e);") {
		t.Fatal("syscall events should be emitted through event v2")
	}
	if !strings.Contains(directHeader, "emit_syscall_enter_event_v2_direct(") ||
		!strings.Contains(straceSource, "emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);") ||
		!strings.Contains(straceSource, "emit_syscall_exit_event_v2_direct(p, ctx->ret, duration, 0);") ||
		!strings.Contains(straceSource, "save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);") ||
		!strings.Contains(straceSource, "is_scalar_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_direct_syscall(p->sys_id)") {
		t.Fatal("scalar syscalls should use direct event v2 helpers instead of the bpf_event carrier")
	}
	if !strings.Contains(directHeader, "return sys_id == SYS_GETPID || sys_id == SYS_CLOSE;") {
		t.Fatal("scalar direct syscall policy should include getpid and close")
	}
	if !strings.Contains(directHeader, "return sys_id == SYS_OPENAT || sys_id == SYS_WRITE || sys_id == SYS_PWRITE64;") ||
		!strings.Contains(straceSource, "is_payload_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_direct_syscall(p->sys_id)") ||
		!strings.Contains(directHeader, "emit_payload_enter_event_v2_direct(") ||
		!strings.Contains(directHeader, "capture_openat_path_tlv_direct(") {
		t.Fatal("payload syscalls should use direct event v2 TLV helpers instead of the bpf_event carrier")
	}
	if !strings.Contains(directHeader, "PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_OPENAT_MAX") ||
		!strings.Contains(directHeader, "bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_OPENAT_MAX)") {
		t.Fatal("openat direct helper should reserve TLV payload capacity and copy path into dynptr data")
	}
	if !strings.Contains(directHeader, "return sys_id == SYS_WRITE || sys_id == SYS_PWRITE64;") ||
		!strings.Contains(directHeader, "capture_write_bytes_tlv_direct(") ||
		!strings.Contains(directHeader, "PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_WRITE_MAX") ||
		!strings.Contains(directHeader, "bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_WRITE_MAX)") ||
		!strings.Contains(directHeader, "record_payload_truncated_event();") {
		t.Fatal("write direct helper should reserve TLV payload capacity, copy bytes, and record truncation")
	}
	if !strings.Contains(directHeader, "return sys_id == SYS_READ || sys_id == SYS_PREAD64;") ||
		!strings.Contains(straceSource, "is_exit_payload_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_exit_payload_direct_syscall(p->sys_id)") ||
		!strings.Contains(straceSource, "ctx->ret > 0") ||
		!strings.Contains(directHeader, "capture_read_bytes_tlv_direct(") ||
		!strings.Contains(directHeader, "emit_payload_exit_event_v2_direct(") ||
		!strings.Contains(directHeader, "PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_READ_MAX") ||
		!strings.Contains(directHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") {
		t.Fatal("read direct helper should reserve exit TLV payload capacity and copy bytes with out direction")
	}
	if !strings.Contains(straceSource, "emit_lifecycle_event_v2_direct(kind, pid, tid, arg0, arg1, snapshot_str);") {
		t.Fatal("lifecycle events should be emitted directly as event v2")
	}
	if strings.Contains(straceSource, "emit_lifecycle_event_v2(e);") {
		t.Fatal("lifecycle events should not use the bpf_event carrier")
	}
	if strings.Contains(straceSource, "emit_legacy_event") {
		t.Fatal("BPF runtime should not retain legacy fixed-window event output")
	}
	if !strings.Contains(straceSource, "EVENT_V2_HEADER_LEN + EVENT_V2_LIFECYCLE_BODY_LEN + payload_capacity") ||
		!strings.Contains(straceSource, "bpf_dynptr_data(&ptr, payload_offset, LIFECYCLE_SNAPSHOT_MAX)") {
		t.Fatal("lifecycle event v2 direct helper should reserve room for direct snapshot payload")
	}
	if !strings.Contains(straceSource, "EVENT_V2_HEADER_LEN + body_size + payload_size") {
		t.Fatal("event v2 output size should be header plus syscall body plus TLV payload")
	}
	wantFlag := "#define EVENT_FLAG_PAYLOAD_TLV " + strconv.Itoa(int(bpfEventFlagPayloadTLV))
	if !strings.Contains(tlvHeader, wantFlag) {
		t.Fatalf("payload TLV header missing %q", wantFlag)
	}
	wantTruncatedFlag := "#define EVENT_FLAG_TRUNCATED " + strconv.Itoa(int(bpfEventFlagTruncated))
	if !strings.Contains(tlvHeader, wantTruncatedFlag) {
		t.Fatalf("payload TLV header missing %q", wantTruncatedFlag)
	}
	if !strings.Contains(tlvHeader, "PAYLOAD_TLV_KIND_STRING") ||
		!strings.Contains(tlvHeader, "PAYLOAD_TLV_KIND_BYTES") {
		t.Fatal("payload TLV header missing string/bytes section kinds")
	}
	if !strings.Contains(tlvHeader, "PAYLOAD_TLV_KIND_EXEC_ARGS") {
		t.Fatal("payload TLV header missing exec args section kind")
	}
	if !strings.Contains(tlvHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") {
		t.Fatal("payload TLV header missing out direction flag")
	}
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
