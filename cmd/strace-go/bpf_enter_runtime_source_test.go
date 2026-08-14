package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEnterRuntimeContractHasDedicatedOwnership(t *testing.T) {
	root := repoRootForTest(t)
	runtimeSource := readTextFile(t, filepath.Join(root, "bpf/enter_runtime.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	fragment := readTextFile(t, filepath.Join(root, "bpf/enter_fragment_dispatch.h"))
	quota := readTextFile(t, filepath.Join(root, "bpf/quota_dispatch.h"))
	mountPath := readTextFile(t, filepath.Join(root, "bpf/mount_path_dispatch.h"))

	for _, snippet := range []string{
		"enum enter_prog_index",
		"#define ENTER_PROLOGUE(ctx)",
		"emit_enter_dispatch_fallback(",
		"emit_no_payload_enter_event_v2_direct(",
		"save_pending_syscall_args(",
	} {
		if !strings.Contains(runtimeSource, snippet) {
			t.Fatalf("enter runtime module missing %q", snippet)
		}
	}
	if !strings.Contains(dispatch, `#include "enter_runtime.h"`) {
		t.Fatal("enter dispatch missing enter runtime include")
	}
	for _, source := range []struct {
		name string
		text string
	}{
		{name: "enter_dispatch.h", text: dispatch},
		{name: "enter_fragment_dispatch.h", text: fragment},
		{name: "quota_dispatch.h", text: quota},
		{name: "mount_path_dispatch.h", text: mountPath},
	} {
		if strings.Contains(source.text, "enum enter_prog_index") ||
			strings.Contains(source.text, "static __always_inline void emit_enter_dispatch_fallback(") {
			t.Fatalf("%s owns enter runtime contract implementation", source.name)
		}
	}
	for _, source := range []string{fragment, quota, mountPath} {
		if !strings.Contains(source, "ENTER_PROLOGUE(ctx);") {
			t.Fatal("enter family handler does not use shared ENTER_PROLOGUE")
		}
	}
	for name, source := range map[string]string{
		"enter_runtime.h":           runtimeSource,
		"enter_dispatch.h":          dispatch,
		"enter_fragment_dispatch.h": fragment,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
