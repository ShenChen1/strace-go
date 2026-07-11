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
	wantFlag := "#define EVENT_FLAG_PAYLOAD_TLV " + strconv.Itoa(int(bpfEventFlagPayloadTLV))
	if !strings.Contains(tlvHeader, wantFlag) {
		t.Fatalf("payload TLV header missing %q", wantFlag)
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
