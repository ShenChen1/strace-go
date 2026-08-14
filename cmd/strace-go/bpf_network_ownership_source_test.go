package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFNetworkHasDedicatedEnterAndExitOwnership(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_network_direct_event_v2.h")
	capture := read("syscall_network_capture_direct_event_v2.h")
	enterEmit := read("syscall_network_emit_direct_event_v2.h")
	exitFacade := read("syscall_network_direct_exit_event_v2.h")
	exitCapture := read("syscall_network_exit_capture_direct_event_v2.h")
	exitEmit := read("syscall_network_exit_emit_direct_event_v2.h")

	for _, include := range []string{
		`#include "syscall_network_capture_direct_event_v2.h"`,
		`#include "syscall_network_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("network facade missing %q", include)
		}
	}
	if strings.Index(facade, "syscall_network_capture_direct_event_v2.h") >
		strings.Index(facade, "syscall_network_emit_direct_event_v2.h") {
		t.Fatal("network facade must include capture before emit")
	}
	for _, include := range []string{
		`#include "syscall_network_exit_capture_direct_event_v2.h"`,
		`#include "syscall_network_exit_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(exitFacade, include) {
			t.Fatalf("network exit facade missing %q", include)
		}
	}
	if strings.Index(exitFacade, "syscall_network_exit_capture_direct_event_v2.h") >
		strings.Index(exitFacade, "syscall_network_exit_emit_direct_event_v2.h") {
		t.Fatal("network exit facade must include capture before emit")
	}

	for _, snippet := range []string{
		"struct network_direct_args",
		"is_network_direct_syscall(",
		"network_direct_enter_socklen_arg(",
		"network_direct_arg(",
		"network_direct_pending_arg(",
		"save_pending_network_syscall_args(",
	} {
		if !strings.Contains(facade, snippet) {
			t.Fatalf("network facade missing policy/state %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_network_enter_payloads_tlv_direct(",
		"capture_network_tlv_direct(",
		"capture_network_socklen_tlv_direct(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("network capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"init_network_enter_event_v2_from_args(",
		"emit_network_enter_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_network_enter_payloads_tlv_direct(",
	} {
		if !strings.Contains(enterEmit, snippet) {
			t.Fatalf("network enter emit provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_network_getsockopt_exit_tlv_direct(",
		"capture_network_exit_payloads_tlv_direct(",
		"capture_network_tlv_direct(",
	} {
		if !strings.Contains(exitCapture, snippet) {
			t.Fatalf("network exit capture provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_network_exit_event_v2_direct(",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_ringbuf_submit_dynptr(",
		"capture_network_exit_payloads_tlv_direct(",
	} {
		if !strings.Contains(exitEmit, snippet) {
			t.Fatalf("network exit emit provider missing %q", snippet)
		}
	}

	for _, source := range []struct {
		name string
		text string
	}{
		{name: "facade", text: facade},
		{name: "exit facade", text: exitFacade},
	} {
		for _, definition := range []string{
			"static __always_inline u32 capture_network_enter_payloads_tlv_direct(",
			"static __always_inline void emit_network_enter_event_v2_direct(",
			"static __always_inline u32 capture_network_exit_payloads_tlv_direct(",
			"static __always_inline void emit_network_exit_event_v2_direct(",
		} {
			if strings.Contains(source.text, definition) {
				t.Fatalf("network %s still owns implementation %q", source.name, definition)
			}
		}
	}
	if strings.Contains(capture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(capture, "bpf_ringbuf_submit_dynptr(") ||
		strings.Contains(capture, "emit_network_enter_event_v2_direct(") {
		t.Fatal("network enter capture provider must not own ringbuf lifecycle or emitter")
	}
	if strings.Contains(enterEmit, "bpf_probe_read_user(") ||
		strings.Contains(enterEmit, "bpf_probe_read_user_str(") {
		t.Fatal("network enter emit provider must not own user memory reads")
	}
	if strings.Contains(exitCapture, "bpf_ringbuf_reserve_dynptr(") ||
		strings.Contains(exitCapture, "bpf_ringbuf_submit_dynptr(") ||
		strings.Contains(exitCapture, "emit_network_exit_event_v2_direct(") {
		t.Fatal("network exit capture provider must not own ringbuf lifecycle or emitter")
	}
	if strings.Contains(exitEmit, "bpf_probe_read_user(") ||
		strings.Contains(exitEmit, "bpf_probe_read_user_str(") {
		t.Fatal("network exit emit provider must not own user memory reads")
	}

	for name, source := range map[string]string{
		"facade": facade, "capture": capture, "enter emit": enterEmit,
		"exit facade": exitFacade, "exit capture": exitCapture, "exit emit": exitEmit,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("network %s provider lines = %d, want <= 500", name, lines)
		}
	}
}
