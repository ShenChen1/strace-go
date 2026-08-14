package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMsgDirectModulesOwnResponsibilities(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}

	facade := read("syscall_msg_direct_event_v2.h")
	core := read("syscall_msg_core_direct_event_v2.h")
	capture := read("syscall_msg_capture_direct_event_v2.h")
	mmsgCapture := read("syscall_mmsg_capture_direct_event_v2.h")
	mmsgStructCapture := read("syscall_mmsg_struct_capture_direct_event_v2.h")
	mmsgBytesCapture := read("syscall_mmsg_bytes_capture_direct_event_v2.h")
	enter := read("syscall_msg_enter_direct_event_v2.h")
	bytesEnter := read("syscall_mmsg_bytes_enter_direct_event_v2.h")
	exit := read("syscall_msg_exit_direct_event_v2.h")
	recvExit := read("syscall_msg_recv_exit_direct_event_v2.h")
	mmsgExit := read("syscall_mmsg_exit_direct_event_v2.h")

	for name, source := range map[string]string{
		"syscall_msg_direct_event_v2.h":                 facade,
		"syscall_msg_core_direct_event_v2.h":            core,
		"syscall_msg_capture_direct_event_v2.h":         capture,
		"syscall_mmsg_capture_direct_event_v2.h":        mmsgCapture,
		"syscall_mmsg_struct_capture_direct_event_v2.h": mmsgStructCapture,
		"syscall_mmsg_bytes_capture_direct_event_v2.h":  mmsgBytesCapture,
		"syscall_msg_enter_direct_event_v2.h":           enter,
		"syscall_mmsg_bytes_enter_direct_event_v2.h":    bytesEnter,
		"syscall_msg_exit_direct_event_v2.h":            exit,
		"syscall_msg_recv_exit_direct_event_v2.h":       recvExit,
		"syscall_mmsg_exit_direct_event_v2.h":           mmsgExit,
	} {
		if !strings.Contains(source, "#ifndef STRACE_GO_") || !strings.Contains(source, "#endif") {
			t.Fatalf("%s must have an include guard", name)
		}
	}

	orderedIncludes := []string{
		`#include "syscall_msg_core_direct_event_v2.h"`,
		`#include "syscall_msg_capture_direct_event_v2.h"`,
		`#include "syscall_mmsg_capture_direct_event_v2.h"`,
		`#include "syscall_msg_enter_direct_event_v2.h"`,
		`#include "syscall_mmsg_bytes_enter_direct_event_v2.h"`,
		`#include "syscall_msg_exit_direct_event_v2.h"`,
	}
	previous := -1
	for _, include := range orderedIncludes {
		current := strings.Index(facade, include)
		if current < 0 || current <= previous {
			t.Fatalf("msg facade include order is invalid at %q", include)
		}
		previous = current
	}
	for _, snippet := range []string{
		`#include "syscall_msg_control_direct_event_v2.h"`,
		"is_msg_direct_syscall(",
		"msg_direct_read_iov(",
		"save_pending_msg_syscall_args(",
	} {
		if !strings.Contains(core, snippet) {
			t.Fatalf("msg core module missing %q", snippet)
		}
	}
	for _, include := range []string{
		`#include "syscall_msg_recv_exit_direct_event_v2.h"`,
		`#include "syscall_mmsg_exit_direct_event_v2.h"`,
	} {
		if !strings.Contains(exit, include) {
			t.Fatalf("msg exit facade missing %q", include)
		}
	}
	for _, snippet := range []string{
		"capture_msghdr_tlv_direct(",
		"capture_single_msg_exit_payloads_tlv_direct(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("msg capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_mmsg_enter_payloads_tlv_direct(",
		"capture_mmsg_base1_enter_payloads_tlv_direct(",
		"capture_mmsg_base3_enter_payloads_tlv_direct(",
		"capture_mmsg_exit_payloads_tlv_direct(",
	} {
		if !strings.Contains(mmsgStructCapture, snippet) {
			t.Fatalf("mmsg capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_recvmmsg_base1_exit_payloads_tlv_direct(",
		"capture_recvmmsg_base3_exit_payloads_tlv_direct(",
	} {
		if !strings.Contains(mmsgBytesCapture, snippet) {
			t.Fatalf("mmsg bytes capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_msg_enter_event_v2_direct(",
		"emit_mmsg_enter_event_v2_direct(",
		"emit_mmsg_base1_enter_event_v2_direct(",
	} {
		if !strings.Contains(enter, snippet) {
			t.Fatalf("msg enter module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_mmsg_bytes_base0_enter_event_v2_direct(",
		"emit_mmsg_bytes_base3_enter_event_v2_direct(",
	} {
		if !strings.Contains(bytesEnter, snippet) {
			t.Fatalf("mmsg bytes enter module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_recvmsg_control_exit_fragment_event_v2_direct(",
		"emit_single_msg_exit_event_v2_direct(",
	} {
		if !strings.Contains(recvExit, snippet) {
			t.Fatalf("recvmsg exit module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_mmsg_exit_event_v2_direct(",
		"emit_recvmmsg_base1_exit_fragment_event_v2_direct(",
	} {
		if !strings.Contains(mmsgExit, snippet) {
			t.Fatalf("mmsg exit module missing %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"static __always_inline int is_msg_direct_syscall(",
		"static __always_inline u32 capture_msghdr_tlv_direct(",
		"static __always_inline void emit_msg_enter_event_v2_direct(",
		"static __always_inline void emit_mmsg_exit_event_v2_direct(",
	} {
		if strings.Contains(facade, forbidden) {
			t.Fatalf("msg facade must not own implementation %q", forbidden)
		}
	}
}

func TestBPFMsgDirectModulesStayWithinFileLimit(t *testing.T) {
	root := repoRootForTest(t)
	for _, name := range []string{
		"syscall_msg_direct_event_v2.h",
		"syscall_msg_core_direct_event_v2.h",
		"syscall_msg_capture_direct_event_v2.h",
		"syscall_mmsg_capture_direct_event_v2.h",
		"syscall_mmsg_struct_capture_direct_event_v2.h",
		"syscall_mmsg_bytes_capture_direct_event_v2.h",
		"syscall_msg_enter_direct_event_v2.h",
		"syscall_mmsg_bytes_enter_direct_event_v2.h",
		"syscall_msg_exit_direct_event_v2.h",
		"syscall_msg_recv_exit_direct_event_v2.h",
		"syscall_mmsg_exit_direct_event_v2.h",
	} {
		source := readTextFile(t, filepath.Join(root, "bpf", name))
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
