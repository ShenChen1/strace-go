package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPollNestedFDPathUsesProbeSiteFragments(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, name))
	}

	pollCapture := read("bpf/syscall_poll_capture_direct_event_v2.h")
	pollDirect := read("bpf/syscall_poll_direct_event_v2.h")
	pathCapture := read("bpf/syscall_fd_path_capture_direct_event_v2.h")
	enter := read("bpf/enter_dispatch.h")
	dispatch := read("bpf/nested_fd_path_dispatch.h")
	pathEmit := read("bpf/syscall_fd_path_emit_direct_event_v2.h")
	runtime := read("bpf/runtime_abi.h")

	for _, snippet := range []string{
		"collect_poll_fd_path_candidates_direct(",
		"poll_fd_path_scan_callback(",
		"bpf_loop(POLL_DIRECT_FD_SLOT_MAX",
		"bpf_probe_read_user(&fd",
		"fd_path_nested_add_poll_candidate(",
		"FD_PATH_NESTED_MAX",
	} {
		if !strings.Contains(pollCapture, snippet) &&
			!strings.Contains(pollDirect, snippet) &&
			!strings.Contains(pathCapture, snippet) {
			t.Fatalf("poll nested path capture missing %q", snippet)
		}
	}

	enterBody, ok := bpfFunctionBody(enter, "enter_poll")
	if !ok {
		t.Fatal("poll enter handler is missing")
	}
	scanBody, ok := bpfFunctionBody(pollCapture, "poll_fd_path_scan_callback")
	if !ok {
		t.Fatal("poll fd path scan callback is missing")
	}
	if !strings.Contains(scanBody, "if (index >= scan->count)") {
		t.Fatal("poll fd path scan must stop only after the user array is exhausted")
	}
	if strings.Contains(scanBody, "nested_fd_count >= FD_PATH_NESTED_MAX") {
		t.Fatal("poll fd path scan must continue after the four-candidate window is full")
	}
	collect := strings.Index(enterBody, "collect_poll_fd_path_candidates_direct(")
	emit := strings.Index(enterBody, "emit_poll_enter_event_v2_direct(")
	save := strings.Index(enterBody, "save_pending_syscall_args(")
	tail := strings.Index(enterBody, "ENTER_PROG_NESTED_FD_PATH0")
	if collect < 0 || emit <= collect || save <= emit || tail <= save {
		t.Fatalf("poll nested path order is invalid: collect=%d emit=%d save=%d tail=%d", collect, emit, save, tail)
	}
	if !strings.Contains(enterBody, "CONFIG_FD_STATE") {
		t.Fatal("poll nested path capture must be gated by CONFIG_FD_STATE")
	}

	for index := 0; index < 4; index++ {
		name := "enter_nested_fd_path" + string(rune('0'+index))
		if !strings.Contains(dispatch, "int "+name+"(") {
			t.Fatalf("nested path fragment %s is missing", name)
		}
	}
	for _, snippet := range []string{
		"emit_nested_fd_path_fragment_event_v2_direct(",
		"EVENT_FLAG_EXIT_FRAGMENT",
		"PAYLOAD_TLV_FD_PATH_NESTED_ARG_INDEX",
		"bpf_ringbuf_reserve_dynptr(",
	} {
		if !strings.Contains(pathEmit, snippet) {
			t.Fatalf("nested path emitter missing %q", snippet)
		}
	}
	if !strings.Contains(runtime, "__uint(max_entries, 51)") {
		t.Fatal("enter ProgArray does not reserve four nested path fragment slots")
	}
}
