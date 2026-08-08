package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMsgPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	// IMPACT: raw syscall program attachment lives in bpf_attach.go; session.go
	// delegates to the attacher. The gate scans both files for wiring snippets.
	sessionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/session.go")) +
		"\n" + readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_attach.go"))
	msgDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_msg_direct_event_v2.h"))
	msgControlHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_msg_control_direct_event_v2.h"))
	msgDirectSources := msgDirectHeader + "\n" + msgControlHeader
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)

	for _, snippet := range []string{
		"#define SYS_SENDMSG 46",
		"#define SYS_RECVMSG 47",
		"#define SYS_RECVMMSG 299",
		"#define SYS_SENDMMSG 307",
		`#include "syscall_msg_direct_event_v2.h"`,
		"is_msg_direct_syscall(sys_id)",
		"is_single_msg_direct_syscall(sys_id)",
		"enter_msg",
		"enter_sendmsg_base",
		"enter_mmsg",
		"enter_sendmmsg_base0",
		"enter_sendmmsg_base1",
		"exit_msg",
		"exit_recvmmsg_base0",
		"exit_recvmmsg_base1",
		"trace_kretprobe_recvmsg_name",
		"trace_kretprobe_recvmsg_control",
		"exit_mmsg",
		"emit_msg_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_sendmsg_base_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_mmsg_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"save_pending_msg_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);",
		"emit_sendmmsg_base0_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_sendmmsg_base1_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_single_msg_exit_event_v2_direct(p, ret_value, duration);",
		"emit_recvmsg_name_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_recvmsg_control_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_recvmmsg_base0_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_recvmmsg_base1_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_mmsg_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) {
			t.Fatalf("BPF source missing msg direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"EnterMsg",
		"objs.EnterMsg",
		"EnterSendmsgBase",
		"objs.EnterSendmsgBase",
		"EnterMmsg",
		"objs.EnterMmsg",
		"EnterSendmmsgBase0",
		"objs.EnterSendmmsgBase0",
		"EnterSendmmsgBase1",
		"objs.EnterSendmmsgBase1",
		"ExitMsg",
		"TraceKretprobeRecvmsgName",
		"attachRecvmsgNameKretprobe",
		"TraceKretprobeRecvmsgControl",
		"attachRecvmsgControlKretprobe",
		"ExitRecvmmsgBase0",
		"objs.ExitRecvmmsgBase0",
		"ExitRecvmmsgBase1",
		"objs.ExitRecvmmsgBase1",
		"ExitMmsg",
	} {
		if !strings.Contains(sessionSource, snippet) {
			t.Fatalf("session source missing msg attach snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"MSGHDR_USER_SIZE 56",
		"MMSGHDR_USER_SIZE 64",
		"MMSGHDR_DIRECT_SLOT_MAX 2",
		"MMSGHDR_SECOND_IOV_ARG 151",
		"MSG_DIRECT_SOCKADDR_MAX 128",
		"MSG_DIRECT_TIMESPEC_SIZE 16",
		"MSG_DIRECT_TIMESPEC_MAX",
		`#include "syscall_msg_control_direct_event_v2.h"`,
		"MSG_DIRECT_CMSG_MAX 256",
		"MSG_DIRECT_CMSG_TLV_MAX",
		"MSG_DIRECT_SINGLE_ENTER_MAX",
		"MSG_DIRECT_ENTER_MAX",
		"MSG_DIRECT_SENDMSG_BASE_ENTER_MAX",
		"MSG_DIRECT_SENDMMSG_BASE_ENTER_MAX",
		"MSG_DIRECT_RECVMSG_EXIT_MAX",
		"MSG_DIRECT_RECVMSG_NAME_EXIT_MAX",
		"MSG_DIRECT_RECVMSG_CONTROL_EXIT_MAX",
		"MSG_DIRECT_MMSG_EXIT_MAX",
		"MSG_DIRECT_RECVMMSG_BASE_EXIT_MAX",
		"is_single_msg_direct_syscall(",
		"msg_direct_read_name(",
		"save_pending_msg_syscall_args(",
		"capture_msghdr_tlv_direct(",
		"capture_msg_name_tlv_direct(",
		"capture_msg_control_tlv_direct(",
		"PAYLOAD_TLV_KIND_CMSG",
		"capture_mmsg_timespec_tlv_direct(",
		"emit_recvmsg_name_exit_fragment_event_v2_direct(",
		"capture_mmsghdr_tlv_direct(",
		"capture_single_msg_enter_payloads_tlv_direct(",
		"capture_sendmsg_base_enter_payloads_tlv_direct(",
		"capture_mmsg_enter_payloads_tlv_direct(",
		"capture_sendmmsg_base0_enter_payloads_tlv_direct(",
		"capture_sendmmsg_base1_enter_payloads_tlv_direct(",
		"capture_single_msg_exit_payloads_tlv_direct(",
		"emit_recvmsg_control_exit_fragment_event_v2_direct(",
		"capture_mmsg_exit_payloads_tlv_direct(",
		"capture_recvmmsg_base0_exit_payloads_tlv_direct(",
		"capture_recvmmsg_base1_exit_payloads_tlv_direct(",
		"capture_iovec_tlv_direct(",
		"capture_iovec_base_payloads_tlv_direct(",
		"capture_iovec_base_payloads_arg151_tlv_direct(",
		"capture_iovec_base_exit_payloads_tlv_direct(",
		"capture_iovec_base_exit_payloads_arg151_tlv_direct(",
		"EVENT_FLAG_EXIT_FRAGMENT",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_KIND_STRUCT,\n            4,",
		"PAYLOAD_TLV_KIND_SOCKADDR",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"capture_mmsg_exit_payloads_tlv_direct(&ptr, payload_offset, p, ret_value, &flags);",
	} {
		if !strings.Contains(msgDirectSources, snippet) {
			t.Fatalf("msg direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [sendmsg, recvmsg]",
		"syscalls: [sendmmsg, recvmmsg]",
		"case 46: /* sendmsg */",
		"case 47: /* recvmsg */",
		"case 299: /* recvmmsg */",
		"case 307: /* sendmmsg */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("msg syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}

func TestBPFRecvmmsgExitChainHasFinalFallback(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	for _, name := range []string{"exit_recvmmsg_base0", "exit_recvmmsg_base1"} {
		body, ok := bpfFunctionBody(source, name)
		if !ok {
			t.Fatalf("exit_dispatch.h missing function body for %s", name)
		}
		if !strings.Contains(body, "emit_mmsg_exit_event_v2_direct(p, ret_value, duration);") {
			t.Fatalf("%s lacks final mmsg fallback after tail-call failure", name)
		}
		if !strings.Contains(body, "consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);") {
			t.Fatalf("%s lacks pending cleanup after final fallback", name)
		}
	}
}

func bpfFunctionBody(source string, name string) (string, bool) {
	start := strings.Index(source, name+"(")
	if start < 0 {
		return "", false
	}
	end := strings.Index(source[start:], "\nSEC(")
	if end < 0 {
		end = strings.Index(source[start:], "\n#endif")
		if end < 0 {
			end = len(source[start:])
		}
	}
	return source[start : start+end], true
}
