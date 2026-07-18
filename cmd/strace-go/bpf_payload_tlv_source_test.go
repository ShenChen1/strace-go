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

	if !strings.Contains(straceSource, `#include "payload_tlv.h"`) {
		t.Fatal("strace.c does not include payload_tlv.h")
	}
	if !strings.Contains(straceSource, "#define SYS_READ 0") {
		t.Fatal("strace.c missing SYS_READ constant for read TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_PREAD64 17") {
		t.Fatal("strace.c missing SYS_PREAD64 constant for pread64 TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_PWRITE64 18") {
		t.Fatal("strace.c missing SYS_PWRITE64 constant for pwrite64 TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_OPENAT 257") {
		t.Fatal("strace.c missing SYS_OPENAT constant for openat TLV capture")
	}
	if !strings.Contains(tlvHeader, "e->sys_id != SYS_WRITE && e->sys_id != SYS_PWRITE64") {
		t.Fatal("write TLV helper should cover write and pwrite64")
	}
	if !strings.Contains(tlvHeader, "e->sys_id != SYS_READ && e->sys_id != SYS_PREAD64") {
		t.Fatal("read TLV helper should cover read and pread64")
	}
	if calls := strings.Count(straceSource, "capture_openat_tlv(e);"); calls != 1 {
		t.Fatalf("capture_openat_tlv calls = %d, want enter path only", calls)
	}
	if calls := strings.Count(straceSource, "capture_write_tlv(e);"); calls != 2 {
		t.Fatalf("capture_write_tlv calls = %d, want enter and exit paths", calls)
	}
	if calls := strings.Count(straceSource, "capture_read_tlv(e);"); calls != 1 {
		t.Fatalf("capture_read_tlv calls = %d, want exit path only", calls)
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
	if !strings.Contains(straceSource, "e->event_type == EVENT_TYPE_ENTER || e->event_type == EVENT_TYPE_EXIT") {
		t.Fatal("truncated stats should ignore lifecycle action ids sharing event_flags")
	}
	if !strings.Contains(straceSource, "emit_syscall_event_v2(e);") {
		t.Fatal("syscall events should be emitted through event v2")
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
	if !strings.Contains(tlvHeader, "payload_tlv_mark_truncated(e, user_len, copied_len, probe_ret)") {
		t.Fatal("read/write TLV helpers should mark truncated payload events")
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
