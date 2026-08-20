package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEpollNestedFDPathUsesExitFragments(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, name))
	}

	capture := read("bpf/syscall_epoll_capture_direct_event_v2.h")
	exitDispatch := read("bpf/nested_fd_path_exit_dispatch.h")
	exitDirect := read("bpf/exit_direct_dispatch.h")
	runtime := read("bpf/runtime_abi.h")
	attach := read("bpf/handlers_exit.c")

	for _, snippet := range []string{
		"collect_epoll_fd_path_candidates_direct(",
		"struct epoll_fd_path_scan_context",
		"epoll_fd_path_scan_callback(",
		"bpf_loop(EPOLL_DIRECT_EVENT_SLOT_MAX",
		"bpf_probe_read_user(\n            &fd,",
		"fd_path_nested_add_window_candidate(",
		"FD_STATE_MAX_FD",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("epoll capture is missing %q", snippet)
		}
	}

	for index := 0; index < 4; index++ {
		name := "exit_nested_fd_path" + string(rune('0'+index))
		if !strings.Contains(exitDispatch, "int "+name+"(") {
			t.Fatalf("exit nested path fragment %s is missing", name)
		}
	}
	for _, snippet := range []string{
		"lookup_pending_syscall_for_exit(",
		"emit_nested_fd_path_fragment_event_v2_direct(",
		"bpf_tail_call(ctx, &exit_progs, EXIT_PROG_NESTED_FD_PATH1)",
		"emit_epoll_wait_exit_event_v2_direct(",
		"consume_pending_syscall(",
	} {
		if !strings.Contains(exitDispatch, snippet) {
			t.Fatalf("exit nested dispatcher is missing %q", snippet)
		}
	}

	body, ok := bpfFunctionBody(exitDirect, "exit_io")
	if !ok {
		t.Fatal("exit_io handler is missing")
	}
	assertBPFSourceOrder(t, body, []string{
		"collect_epoll_fd_path_candidates_direct(",
		"volatile tail_ctx = ctx",
		"EXIT_PROG_NESTED_FD_PATH0",
		"emit_epoll_wait_exit_event_v2_direct(",
		"consume_pending_syscall(",
	})

	if !strings.Contains(attach, `#include "nested_fd_path_exit_dispatch.h"`) {
		t.Fatal("exit handler does not own nested exit dispatcher")
	}
	if !strings.Contains(runtime, "__uint(max_entries, 18)") {
		t.Fatal("exit_progs map must reserve four nested exit fragment slots")
	}
}
