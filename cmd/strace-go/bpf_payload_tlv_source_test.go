package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestBPFWritePayloadUsesTLVFlag(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	tlvHeader := readTextFile(t, filepath.Join(root, "bpf/payload_tlv.h"))

	if !strings.Contains(straceSource, `#include "payload_tlv.h"`) {
		t.Fatal("strace.c does not include payload_tlv.h")
	}
	if calls := strings.Count(straceSource, "capture_write_tlv(e);"); calls != 2 {
		t.Fatalf("capture_write_tlv calls = %d, want enter and exit paths", calls)
	}
	if !strings.Contains(straceSource, "saved_flags | EVENT_FLAG_GENERIC_ENTER") {
		t.Fatal("generic enter flag should preserve payload TLV flag")
	}
	wantFlag := "#define EVENT_FLAG_PAYLOAD_TLV " + strconv.Itoa(int(bpfEventFlagPayloadTLV))
	if !strings.Contains(tlvHeader, wantFlag) {
		t.Fatalf("payload TLV header missing %q", wantFlag)
	}
	if !strings.Contains(tlvHeader, "PAYLOAD_TLV_KIND_BYTES") {
		t.Fatal("payload TLV header missing bytes section kind")
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
