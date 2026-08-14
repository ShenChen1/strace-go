package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEnterDispatcherFallbackIsIsolated(t *testing.T) {
	source := loadBPFSources(t).straceSource
	dispatcher, ok := bpfFunctionBody(source, "trace_sys_enter")
	if !ok {
		t.Fatal("strace.c missing trace_sys_enter body")
	}
	call := "emit_enter_dispatch_fallback(ctx, pid, tid, cfg, enter_time);"
	if !strings.Contains(dispatcher, call) {
		t.Fatalf("trace_sys_enter missing fallback helper call %q", call)
	}
	for _, inline := range []string{
		"emit_no_payload_enter_event_v2_direct(",
		"save_pending_syscall_args(",
	} {
		if strings.Contains(dispatcher, inline) {
			t.Fatalf("trace_sys_enter still owns fallback detail %q", inline)
		}
	}

	enterSource := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/enter_runtime.h"))
	helper, ok := bpfFunctionBody(enterSource, "emit_enter_dispatch_fallback")
	if !ok {
		t.Fatal("BPF source missing emit_enter_dispatch_fallback")
	}
	assertBPFSourceOrder(t, helper, []string{
		"volatile s32 stack_id = -1;",
		"emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);",
		"save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);",
	})
}

func TestBPFExitDispatchFallbackOwnsPending(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/exit_dispatch.h"))
	body, ok := bpfFunctionBody(source, "emit_exit_dispatch_fallback")
	if !ok {
		t.Fatal("BPF source missing emit_exit_dispatch_fallback")
	}
	assertBPFSourceOrder(t, body, []string{
		"lookup_pending_syscall_for_exit(",
		"validate_pending_syscall_exit(",
		"emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);",
		"consume_pending_syscall(pid, pending_tid, p, pending_exec_lookup);",
	})
}

func assertBPFSourceOrder(t *testing.T, body string, snippets []string) {
	t.Helper()
	last := -1
	for _, snippet := range snippets {
		index := strings.Index(body, snippet)
		if index < 0 {
			t.Fatalf("BPF source missing ordered snippet %q", snippet)
		}
		if index <= last {
			t.Fatalf("BPF source order moved at %q", snippet)
		}
		last = index
	}
}
