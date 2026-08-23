package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfObjInfoExitProviderUsesBoundedOutTLV(t *testing.T) {
	root := repoRootForTest(t)
	direct := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_direct_event_v2.h"))
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	combined := direct + "\n" + exit

	for _, snippet := range []string{
		`#include "syscall_bpf_exit_direct_event_v2.h"`,
		"emit_bpf_exit_event_v2_direct(",
	} {
		if !strings.Contains(combined, snippet) {
			t.Fatalf("BPF direct facade missing %q", snippet)
		}
	}

	for _, snippet := range []string{
		"BPF_DIRECT_OBJ_GET_INFO_BY_FD 15",
		"BPF_DIRECT_OBJ_INFO_ARG 113",
		"BPF_DIRECT_OBJ_INFO_MAX 512",
		"BPF_DIRECT_OBJ_INFO_LEN_OFF 4",
		"BPF_DIRECT_OBJ_INFO_PTR_OFF 8",
		"ret_value != 0",
		"bpf_attr_read_u32_direct(",
		"bpf_attr_read_u64_direct(",
		"bpf_probe_read_user(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"PAYLOAD_TLV_KIND_BYTES",
		"init_syscall_exit_event_v2_from_pending(",
		"record_payload_truncated_event();",
	} {
		if !strings.Contains(exit, snippet) {
			t.Fatalf("BPF info exit provider missing %q", snippet)
		}
	}
	if !strings.Contains(dispatch, "emit_bpf_exit_event_v2_direct(p, ret_value, duration)") {
		t.Fatal("exit IO family must dispatch BPF object info output")
	}
}

func TestBPFBpfProgLoadExitProviderUsesVerifierLogOutTLV(t *testing.T) {
	root := repoRootForTest(t)
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_PROG_LOAD 5",
		"BPF_DIRECT_PROG_LOAD_LOG_BUF_ARG 102",
		"BPF_DIRECT_PROG_LOAD_LOG_SIZE_OFF 28",
		"BPF_DIRECT_PROG_LOAD_LOG_BUF_OFF 32",
		"BPF_DIRECT_PROG_LOAD_LOG_TRUE_SIZE_OFF 140",
		"BPF_DIRECT_PROG_LOAD_LOG_MAX 256",
	} {
		if !strings.Contains(nested+exit, snippet) {
			t.Fatalf("BPF prog-load exit provider missing %q", snippet)
		}
	}

	for _, snippet := range []string{
		"emit_bpf_prog_load_log_exit_event_v2_direct(",
		"ret_value >= 0",
		"bpf_probe_read_user(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"PAYLOAD_TLV_KIND_BYTES",
		"init_syscall_exit_event_v2_from_pending(",
		"bpf_ringbuf_discard_dynptr(",
	} {
		if !strings.Contains(exit, snippet) {
			t.Fatalf("BPF prog-load exit provider missing %q", snippet)
		}
	}
	if !strings.Contains(dispatch, "emit_bpf_exit_event_v2_direct(p, ret_value, duration)") {
		t.Fatal("exit IO family must dispatch BPF verifier log output")
	}
}

func TestBPFBpfBtfLoadExitProviderUsesVerifierLogOutTLV(t *testing.T) {
	root := repoRootForTest(t)
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_BTF_LOAD 18",
		"BPF_DIRECT_BTF_LOG_BUF_ARG 114",
		"BPF_DIRECT_BTF_LOG_SIZE_OFF 20",
		"BPF_DIRECT_BTF_LOG_BUF_OFF 8",
		"BPF_DIRECT_BTF_LOG_TRUE_SIZE_OFF 28",
		"BPF_DIRECT_BTF_LOG_MAX 256",
	} {
		if !strings.Contains(nested+exit, snippet) {
			t.Fatalf("BPF BTF-load exit provider missing %q", snippet)
		}
	}

	for _, snippet := range []string{
		"emit_bpf_btf_load_log_exit_event_v2_direct(",
		"ret_value >= 0",
		"bpf_probe_read_user(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"PAYLOAD_TLV_KIND_BYTES",
		"init_syscall_exit_event_v2_from_pending(",
	} {
		if !strings.Contains(exit, snippet) {
			t.Fatalf("BPF BTF-load exit provider missing %q", snippet)
		}
	}
	if !strings.Contains(dispatch, "emit_bpf_exit_event_v2_direct(p, ret_value, duration)") {
		t.Fatal("exit IO family must dispatch BPF BTF log output")
	}
}

func TestBPFBpfTestRunExitProviderUsesBoundedOutTLVs(t *testing.T) {
	root := repoRootForTest(t)
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	testRun := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_test_run_exit_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_PROG_TEST_RUN 10",
		"BPF_DIRECT_TEST_RUN_DATA_ARG 115",
		"BPF_DIRECT_TEST_RUN_CTX_ARG 116",
		"BPF_DIRECT_TEST_RUN_DATA_SIZE_OUT_OFF 12",
		"BPF_DIRECT_TEST_RUN_DATA_OUT_OFF 24",
		"BPF_DIRECT_TEST_RUN_CTX_SIZE_OUT_OFF 44",
		"BPF_DIRECT_TEST_RUN_CTX_OUT_OFF 56",
		"BPF_DIRECT_TEST_RUN_OUTPUT_MAX 512",
	} {
		if !strings.Contains(nested+exit+testRun, snippet) {
			t.Fatalf("BPF test-run exit provider missing %q", snippet)
		}
	}

	for _, snippet := range []string{
		"emit_bpf_prog_test_run_exit_event_v2_direct(",
		"ret_value != 0",
		"bpf_probe_read_user(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"PAYLOAD_TLV_KIND_BYTES",
		"init_syscall_exit_event_v2_from_pending(",
		"bpf_ringbuf_discard_dynptr(",
	} {
		if !strings.Contains(testRun+exit, snippet) {
			t.Fatalf("BPF test-run exit provider missing %q", snippet)
		}
	}
	if !strings.Contains(dispatch, "emit_bpf_exit_event_v2_direct(p, ret_value, duration)") {
		t.Fatal("exit IO family must dispatch BPF test-run output")
	}
}
