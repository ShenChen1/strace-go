package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFGenericExitOwnsPendingAroundEmissionHelper(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	generic, ok := bpfFunctionBody(source, "exit_generic")
	if !ok {
		t.Fatal("exit_dispatch.h missing exit_generic")
	}
	if !strings.Contains(generic, "emit_generic_exit_event(p, ret_value, duration);") {
		t.Fatal("exit_generic must delegate direct emission")
	}
	for _, forbidden := range []string{
		"is_sys_exit_direct_syscall(p->sys_id)",
		"is_fd_state_exit_direct_syscall(p->sys_id)",
		"is_exit_payload_direct_syscall(p->sys_id)",
		"is_fcntl_direct_syscall(p->sys_id)",
		"is_network_direct_syscall(p->sys_id)",
		"emit_fd_state_exit_event_v2_direct(",
		"emit_network_exit_event_v2_direct(",
	} {
		if strings.Contains(generic, forbidden) {
			t.Fatalf("exit_generic still owns direct emission detail %q", forbidden)
		}
	}
	assertBPFSourceOrder(t, generic, []string{
		"EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);",
		"emit_generic_exit_event(p, ret_value, duration);",
		"consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);",
	})

	emitter, ok := bpfExactFunctionBody(source, "emit_generic_exit_event")
	if !ok {
		t.Fatal("exit_dispatch.h missing emit_generic_exit_event")
	}
	if !strings.Contains(source, "static __always_inline void emit_generic_exit_event(") {
		t.Fatal("generic emission must be a static inline helper")
	}
	fallback := "emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);"
	if strings.Count(emitter, fallback) != 1 {
		t.Fatal("generic emission helper must emit exactly one generic fallback")
	}
	for _, group := range []string{
		"emit_generic_exit_fd_time_event(",
		"emit_generic_exit_struct_event(",
		"emit_generic_exit_async_event(",
		"emit_generic_exit_io_event(",
		"emit_generic_exit_control_event(",
	} {
		if strings.Contains(emitter, group) {
			t.Fatalf("generic emission helper still owns family dispatch %q", group)
		}
	}
	if strings.Contains(emitter, "consume_pending_syscall(") ||
		strings.Contains(emitter, "lookup_pending_syscall_for_exit(") {
		t.Fatal("generic emission helper must not own pending lifecycle")
	}
	for _, expectation := range genericExitGroupExpectations() {
		assertBPFGenericExitGroup(t, source, expectation)
	}
}

type bpfExitGroupExpectation struct {
	name     string
	snippets []string
}

func genericExitGroupExpectations() []bpfExitGroupExpectation {
	return []bpfExitGroupExpectation{
		{
			name: "emit_generic_exit_fd_time_event",
			snippets: []string{
				"emit_fd_state_exit_event_v2_direct(p, ret_value, duration);",
				"emit_payload_exit_event_v2_direct(p, ret_value, duration);",
				"emit_gettimeofday_exit_event_v2_direct(p, ret_value, duration);",
				"emit_time_struct_exit_event_v2_direct(p, ret_value, duration);",
				"emit_itimer_exit_event_v2_direct(p, ret_value, duration);",
				"emit_timex_exit_event_v2_direct(p, ret_value, duration);",
				"emit_sleep_exit_event_v2_direct(p, ret_value, duration);",
			},
		},
		{
			name: "emit_generic_exit_struct_event",
			snippets: []string{
				"emit_stat_struct_exit_event_v2_direct(p, ret_value, duration);",
				"emit_waitid_exit_event_v2_direct(p, ret_value, duration);",
				"emit_signal_exit_event_v2_direct(p, ret_value, duration);",
				"emit_getcwd_exit_event_v2_direct(p, ret_value, duration);",
				"emit_readlink_exit_event_v2_direct(p, ret_value, duration);",
				"emit_fd_array_exit_event_v2_direct(p, ret_value, duration);",
				"emit_misc_struct_exit_event_v2_direct(p, ret_value, duration);",
			},
		},
		{
			name: "emit_generic_exit_async_event",
			snippets: []string{
				"emit_small_struct_exit_event_v2_direct(p, ret_value, duration);",
				"emit_cachestat_exit_event_v2_direct(p, ret_value, duration);",
				"emit_capability_exit_event_v2_direct(p, ret_value, duration);",
				"emit_prctl_exit_event_v2_direct(p, ret_value, duration);",
				"emit_aio_getevents_exit_event_v2_direct(p, ret_value, duration);",
				"emit_aio_setup_exit_event_v2_direct(p, ret_value, duration);",
				"emit_poll_exit_event_v2_direct(p, ret_value, duration);",
			},
		},
		{
			name: "emit_generic_exit_io_event",
			snippets: []string{
				"emit_select_exit_event_v2_direct(p, ret_value, duration);",
				"emit_epoll_wait_exit_event_v2_direct(p, ret_value, duration);",
				"emit_getdents_exit_event_v2_direct(p, ret_value, duration);",
				"emit_exec_exit_event_v2_direct(p, ret_value, duration);",
				"emit_xattr_get_exit_event_v2_direct(p, ret_value, duration);",
				"emit_xattr_list_exit_event_v2_direct(p, ret_value, duration);",
			},
		},
		{
			name: "emit_generic_exit_control_event",
			snippets: []string{
				"emit_fcntl_exit_event_v2_direct(p, ret_value, duration);",
				"emit_ioctl_exit_event_v2_direct(p, ret_value, duration);",
				"emit_network_exit_event_v2_direct(p, ret_value, duration);",
			},
		},
	}
}

func assertBPFGenericExitGroup(
	t *testing.T,
	source string,
	expectation bpfExitGroupExpectation,
) {
	t.Helper()
	body, ok := bpfExactFunctionBody(source, expectation.name)
	if !ok {
		t.Fatalf("exit_dispatch.h missing %s", expectation.name)
	}
	if !strings.Contains(source, "static __always_inline int "+expectation.name+"(") {
		t.Fatalf("%s must be a static inline helper", expectation.name)
	}
	for _, snippet := range expectation.snippets {
		if !strings.Contains(body, snippet) {
			t.Fatalf("%s missing %q", expectation.name, snippet)
		}
	}
	if strings.Contains(body, "consume_pending_syscall(") ||
		strings.Contains(body, "lookup_pending_syscall_for_exit(") {
		t.Fatalf("%s must not own pending lifecycle", expectation.name)
	}
}

func bpfExactFunctionBody(source string, name string) (string, bool) {
	start := strings.Index(source, name+"(")
	if start < 0 {
		return "", false
	}
	open := strings.Index(source[start:], "{")
	if open < 0 {
		return "", false
	}
	open += start
	depth := 0
	for index := open; index < len(source); index++ {
		switch source[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[start : index+1], true
			}
		}
	}
	return "", false
}
