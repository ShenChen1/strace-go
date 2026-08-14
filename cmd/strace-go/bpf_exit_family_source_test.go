package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFDirectExitFamiliesOwnEmissionOnly(t *testing.T) {
	source := readCombinedBPFSources(t)
	for _, family := range []struct {
		name    string
		emitter string
	}{
		{name: "exit_fd_time", emitter: "emit_generic_exit_fd_time_event(p, ret_value, duration)"},
		{name: "exit_struct", emitter: "emit_generic_exit_struct_event(p, ret_value, duration)"},
		{name: "exit_async", emitter: "emit_generic_exit_async_event(p, ret_value, duration)"},
		{name: "exit_io", emitter: "emit_generic_exit_io_event(p, ret_value, duration)"},
		{name: "exit_control", emitter: "emit_generic_exit_control_event(p, ret_value, duration)"},
	} {
		body, ok := bpfFunctionBody(source, family.name)
		if !ok {
			t.Fatalf("BPF source missing %s", family.name)
		}
		if !strings.Contains(body, "EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);") {
			t.Fatalf("%s must own the exit prologue", family.name)
		}
		if !strings.Contains(body, family.emitter) {
			t.Fatalf("%s missing family emitter %q", family.name, family.emitter)
		}
		if !strings.Contains(body, "emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);") {
			t.Fatalf("%s must retain generic fallback", family.name)
		}
		assertBPFSourceOrder(t, body, []string{
			"EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);",
			family.emitter,
			"consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);",
		})
	}
}

func TestBPFDirectExitFamilyIncludeIsInTranslationUnit(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	if !strings.Contains(source, `#include "exit_direct_dispatch.h"`) {
		t.Fatal("strace.c must include the split direct exit dispatcher")
	}
}
