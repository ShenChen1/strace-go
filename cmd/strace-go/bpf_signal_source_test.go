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

func TestSignalGenerationProjectsChildNotification(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/signal_dispatch.h"))
	for _, required := range []string{
		`SEC("raw_tracepoint/signal_generate")`,
		"SIGNAL_NUMBER_CHLD",
		"BPF_CORE_READ(target, tgid)",
		"BPF_CORE_READ(target, pid)",
		"target_pending_stack_id(tid)",
		"emit_signal_event_v2(pid, tid, &body)",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("signal generator missing %q", required)
		}
	}
}

func TestSignalGenerationDoesNotCaptureGeneratingTaskStack(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/signal_dispatch.h"))
	start := strings.Index(source, "int trace_signal_generate")
	if start < 0 {
		t.Fatal("signal generator function is missing")
	}
	generator := source[start:]
	if strings.Contains(generator, "bpf_get_stackid") {
		t.Fatal("signal generator captures the generating task stack")
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

func TestSignalDeliveryProjectsFaultAddress(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/signal_dispatch.h"))
	if !strings.Contains(source, "_sifields._sigfault._addr") {
		t.Fatal("signal dispatcher does not project the fault address")
	}
}

func TestSignalDeliveryRejectsKernelSiginfoSentinels(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "bpf/signal_dispatch.h"))
	if !strings.Contains(source, "if (info_address <= 1)") {
		t.Fatal("signal dispatcher does not reject kernel siginfo sentinels")
	}
}
