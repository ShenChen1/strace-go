package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFSelectPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	selectDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_select_direct_event_v2.h"))
	selectCaptureHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_select_capture_direct_event_v2.h"))
	selectEmitHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_select_emit_direct_event_v2.h"))
	fdPathEmitHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_emit_direct_event_v2.h"))
	enterHeader := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	runtimeABI := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	selectDirectSources := runtimeABI + "\n" + enterHeader + "\n" + selectDirectHeader + "\n" + selectCaptureHeader + "\n" + selectEmitHeader + "\n" + fdPathEmitHeader

	for _, snippet := range []string{
		"#define SYS_SELECT 23",
		`#include "syscall_select_direct_event_v2.h"`,
		"is_select_direct_syscall(sys_id)",
		"emit_select_enter_event_v2_direct(ctx, pid, tid, enter_time);",
		"is_select_direct_syscall(p->sys_id) && ret_value >= 0",
		"emit_select_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing select direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"SELECT_DIRECT_FDSET_SIZE 128",
		"SELECT_DIRECT_TIMEVAL_SIZE 16",
		"SELECT_DIRECT_FDSET_ARG_BASE 1",
		"SELECT_DIRECT_FDSET_ARG_LAST 3",
		"FD_PATH_NESTED_MAX 4",
		"SELECT_DIRECT_FD_PATH_MAX FD_PATH_NESTED_MAX",
		"is_select_direct_syscall(",
		"select_direct_fdset_user_len(",
		"s32 nfds = (s32)nfds_raw;",
		"capture_select_fdset_tlv_direct(",
		"capture_select_timeout_tlv_direct(",
		"capture_select_payloads_tlv_direct(",
		"collect_select_fdset_candidates_direct(",
		"collect_select_fd_path_candidates_direct(",
		"emit_select_enter_event_v2_direct(",
		"emit_select_exit_event_v2_direct(",
		"PAYLOAD_TLV_KIND_BYTES",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"PAYLOAD_TLV_FD_PATH_NESTED_ARG_INDEX",
		"cfg && (*cfg & CONFIG_FD_STATE)",
		"bpf_probe_read_user(payload_data, 1",
		"bpf_probe_read_user(payload_data, SELECT_DIRECT_FDSET_SIZE",
		"bpf_probe_read_user(payload_data, SELECT_DIRECT_TIMEVAL_SIZE",
		"init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);",
		"body.capture_len = payload_size;",
	} {
		if !strings.Contains(selectDirectSources, snippet) {
			t.Fatalf("select direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [select, _newselect]",
		"case 23: /* select */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("select syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}

func TestBPFSelectPathCaptureUsesTailCallFragments(t *testing.T) {
	root := repoRootForTest(t)
	enter := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	fragments := readTextFile(t, filepath.Join(root, "bpf/nested_fd_path_dispatch.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_select_emit_direct_event_v2.h"))
	enterRuntime := readTextFile(t, filepath.Join(root, "bpf/enter_runtime.h"))
	runtime := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))

	enterBody, ok := bpfFunctionBody(enter, "enter_select")
	if !ok {
		t.Fatal("select enter handler is missing")
	}
	save := strings.Index(enterBody, "save_pending_syscall_args(")
	start := strings.Index(enterBody, "ENTER_PROG_NESTED_FD_PATH0")
	if save < 0 || start <= save {
		t.Fatalf("select fragment order is invalid: save=%d start=%d", save, start)
	}
	for index := 0; index < 4; index++ {
		name := fmt.Sprintf("enter_nested_fd_path%d", index)
		if !strings.Contains(fragments, "int "+name+"(") {
			t.Fatalf("select fragment handler %s is missing", name)
		}
		slot := fmt.Sprintf("ENTER_PROG_NESTED_FD_PATH%d = %d", index, 47+index)
		if !strings.Contains(enterRuntime, slot) {
			t.Fatalf("select fragment slot %d is missing", index)
		}
	}
	pathEmit := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_path_emit_direct_event_v2.h"))
	for _, snippet := range []string{
		"emit_nested_fd_path_fragment_event_v2_direct(",
		"EVENT_FLAG_EXIT_FRAGMENT",
		"PAYLOAD_TLV_FD_PATH_NESTED_ARG_INDEX",
	} {
		if !strings.Contains(pathEmit, snippet) {
			t.Fatalf("nested fragment emitter missing %q", snippet)
		}
	}
	if strings.Contains(emit, "emit_nested_fd_path_fragment_event_v2_direct(") {
		t.Fatal("select emit provider must not own shared nested path emitter")
	}
	if !strings.Contains(runtime, "__uint(max_entries, 51)") {
		t.Fatal("enter ProgArray does not reserve four select path fragment slots")
	}
}
