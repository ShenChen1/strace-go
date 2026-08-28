package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSignalDeliveryUsesTrackedRawTracepoint(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/signal_dispatch.h"))
	for _, required := range []string{
		`SEC("raw_tracepoint/signal_deliver")`,
		"struct kernel_siginfo",
		"is_lifecycle_task_tracked(pid, tid)",
		"CONFIG_EMIT_SIGNAL",
		"emit_signal_event_v2",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("signal dispatcher missing %q", required)
		}
	}
}

func TestSignalDeliveryProjectsSenderForUserCodes(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/signal_dispatch.h"))
	for _, required := range []string{
		"SIGNAL_CODE_USER",
		"SIGNAL_CODE_QUEUE",
		"SIGNAL_CODE_TKILL",
		"_sifields._kill._pid",
		"_sifields._kill._uid",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("signal dispatcher missing sender projection %q", required)
		}
	}
}

func TestSignalDeliveryRejectsKernelSiginfoSentinels(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/signal_dispatch.h"))
	if !strings.Contains(source, "if (info_address <= 1)") {
		t.Fatal("signal dispatcher does not reject kernel siginfo sentinels")
	}
}
