package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMsgExitHasFamilyOwnedEmitters(t *testing.T) {
	root := repoRootForTest(t)
	facade := readTextFile(t, filepath.Join(root, "bpf/syscall_msg_exit_direct_event_v2.h"))
	recv := readTextFile(t, filepath.Join(root, "bpf/syscall_msg_recv_exit_direct_event_v2.h"))
	mmsg := readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_exit_direct_event_v2.h"))

	for _, include := range []string{
		`#include "syscall_msg_recv_exit_direct_event_v2.h"`,
		`#include "syscall_mmsg_exit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("message exit facade missing %q", include)
		}
	}
	for _, snippet := range []string{
		"emit_recvmsg_control_exit_fragment_event_v2_direct(",
		"emit_recvmsg_name_exit_fragment_event_v2_direct(",
		"emit_single_msg_exit_event_v2_direct(",
		"capture_single_msg_exit_payloads_tlv_direct(",
	} {
		if !strings.Contains(recv, snippet) {
			t.Fatalf("recvmsg exit module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_mmsg_exit_event_v2_direct(",
		"emit_recvmmsg_base0_exit_fragment_event_v2_direct(",
		"emit_recvmmsg_base1_exit_fragment_event_v2_direct(",
		"emit_recvmmsg_base2_exit_fragment_event_v2_direct(",
		"emit_recvmmsg_base3_exit_fragment_event_v2_direct(",
		"capture_mmsg_exit_payloads_tlv_direct(",
	} {
		if !strings.Contains(mmsg, snippet) {
			t.Fatalf("mmsg exit module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline void emit_recvmsg_control_exit_fragment_event_v2_direct(",
		"static __always_inline void emit_single_msg_exit_event_v2_direct(",
		"static __always_inline void emit_mmsg_exit_event_v2_direct(",
	} {
		if strings.Contains(facade, snippet) {
			t.Fatalf("message exit facade must not own implementation %q", snippet)
		}
	}
	for _, snippet := range []string{
		"static __always_inline void emit_mmsg_exit_event_v2_direct(",
		"static __always_inline void emit_recvmmsg_base0_exit_fragment_event_v2_direct(",
	} {
		if strings.Contains(recv, snippet) {
			t.Fatalf("recvmsg exit module has mmsg implementation %q", snippet)
		}
	}
	if strings.Contains(mmsg, "static __always_inline void emit_single_msg_exit_event_v2_direct(") {
		t.Fatal("mmsg exit module has recvmsg implementation")
	}

	for name, source := range map[string]string{
		"syscall_msg_exit_direct_event_v2.h":      facade,
		"syscall_msg_recv_exit_direct_event_v2.h": recv,
		"syscall_mmsg_exit_direct_event_v2.h":     mmsg,
	} {
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}

func TestBPFMsgRawExitLeavesRecvmsgToKretprobe(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	body, ok := bpfFunctionBody(source, "exit_msg")
	if !ok {
		t.Fatal("exit_dispatch.h missing exit_msg body")
	}
	if !strings.Contains(body, "if ((u32)ctx->id != SYS_SENDMSG)") {
		t.Fatal("raw message exit must be restricted to sendmsg")
	}
	if strings.Contains(body, "is_single_msg_direct_syscall((u32)ctx->id)") {
		t.Fatal("raw message exit must not claim recvmsg pending state")
	}
	if !strings.Contains(body, "emit_single_msg_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("raw message exit must retain the sendmsg exit emitter")
	}
}
