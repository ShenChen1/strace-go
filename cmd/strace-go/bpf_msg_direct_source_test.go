package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMsgPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	// IMPACT: raw syscall program attachment lives in bpf_attach.go; the gate
	// scans the attacher for generated program wiring snippets.
	sessionSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_attach.go"))
	msgDirectSources := readMsgDirectEventSources(t)
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
		"enter_mmsg_base01",
		"enter_mmsg_base2",
		"enter_mmsg_base3",
		"exit_msg",
		"exit_recvmmsg_base01",
		"exit_recvmmsg_base23",
		"recvmsg_progs",
		"trace_kretprobe_recvmsg_dispatch",
		"trace_kretprobe_recvmsg_name",
		"trace_kretprobe_recvmsg_control",
		"trace_kretprobe_recvmsg_final",
		"exit_mmsg",
		"emit_msg_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_sendmsg_base_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_mmsg_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"save_pending_msg_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);",
		"emit_mmsg_base0_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_mmsg_base1_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_mmsg_base2_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_mmsg_base3_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"emit_single_msg_exit_event_v2_direct(p, ret_value, duration);",
		"emit_recvmsg_name_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_recvmsg_control_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_recvmmsg_base0_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_recvmmsg_base1_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_recvmmsg_base2_exit_fragment_event_v2_direct(p, ret_value, duration);",
		"emit_recvmmsg_base3_exit_fragment_event_v2_direct(p, ret_value, duration);",
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
		"EnterMmsgBase01",
		"objs.EnterMmsgBase01",
		"EnterMmsgBase2",
		"objs.EnterMmsgBase2",
		"EnterMmsgBase3",
		"objs.EnterMmsgBase3",
		"EnterMmsgBytes0",
		"objs.EnterMmsgBytes0",
		"EnterMmsgBytes1",
		"objs.EnterMmsgBytes1",
		"EnterMmsgBytes2",
		"objs.EnterMmsgBytes2",
		"EnterMmsgBytes3",
		"objs.EnterMmsgBytes3",
		"MmsgBytesProgs",
		"objs.MmsgBytesProgs",
		"ExitMsg",
		"RecvmsgProgs",
		"TraceKretprobeRecvmsgDispatch",
		"attachRecvmsgKretprobe",
		"TraceKretprobeRecvmsgName",
		"TraceKretprobeRecvmsgControl",
		"TraceKretprobeRecvmsgFinal",
		"ExitRecvmmsgBase01",
		"objs.ExitRecvmmsgBase01",
		"ExitRecvmmsgBase23",
		"objs.ExitRecvmmsgBase23",
		"ExitMmsg",
	} {
		if !strings.Contains(sessionSource, snippet) {
			t.Fatalf("session source missing msg attach snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"MSGHDR_USER_SIZE 56",
		"MMSGHDR_USER_SIZE 64",
		"MMSGHDR_DIRECT_SLOT_MAX 4",
		"MMSGHDR_SECOND_IOV_ARG 151",
		"MMSGHDR_THIRD_IOV_ARG 181",
		"MMSGHDR_FOURTH_IOV_ARG 211",
		"MSG_DIRECT_SOCKADDR_MAX 128",
		"MSG_DIRECT_TIMESPEC_SIZE 16",
		"MSG_DIRECT_TIMESPEC_MAX",
		`#include "syscall_msg_control_direct_event_v2.h"`,
		"MSG_DIRECT_CMSG_MAX 256",
		"MSG_DIRECT_CMSG_TLV_MAX",
		"MSG_DIRECT_SINGLE_ENTER_MAX",
		"MSG_DIRECT_ENTER_MAX",
		"MSG_DIRECT_SENDMSG_BASE_ENTER_MAX",
		"MSG_DIRECT_MMSG_BASE_ENTER_MAX",
		"MSG_DIRECT_MMSG_BYTES_ENTER_MAX",
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
		"capture_mmsg_base0_enter_payloads_tlv_direct(",
		"capture_mmsg_base1_enter_payloads_tlv_direct(",
		"capture_mmsg_base2_enter_payloads_tlv_direct(",
		"capture_mmsg_base3_enter_payloads_tlv_direct(",
		"capture_single_msg_exit_payloads_tlv_direct(",
		"emit_recvmsg_control_exit_fragment_event_v2_direct(",
		"capture_mmsg_exit_payloads_tlv_direct(",
		"capture_recvmmsg_base0_exit_payloads_tlv_direct(",
		"capture_recvmmsg_base1_exit_payloads_tlv_direct(",
		"capture_recvmmsg_base2_exit_payloads_tlv_direct(",
		"capture_recvmmsg_base3_exit_payloads_tlv_direct(",
		"capture_iovec_tlv_direct(",
		"capture_iovec_base_payloads_tlv_direct(",
		"capture_iovec_base_exit_payloads_tlv_direct(",
		"capture_iovec_base_payloads_tlv_direct_for_arg(",
		"capture_iovec_base_exit_payloads_tlv_direct_for_arg(",
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

func TestBPFMmsgEnterFragmentsBoundVerifierState(t *testing.T) {
	root := repoRootForTest(t)
	combined := readCombinedBPFSources(t)
	core := readTextFile(t, filepath.Join(root, "bpf/syscall_msg_core_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_capture_direct_event_v2.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/mmsg_enter_dispatch.h"))
	runtimeABI := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))

	for _, snippet := range []string{
		"MSG_DIRECT_MMSG_BASE_ENTER_MAX",
		"capture_mmsg_base_slot_enter_payloads_tlv_direct(",
		"capture_mmsg_base0_enter_payloads_tlv_direct(",
		"capture_mmsg_base1_enter_payloads_tlv_direct(",
		"capture_mmsg_base2_enter_payloads_tlv_direct(",
		"capture_mmsg_base3_enter_payloads_tlv_direct(",
	} {
		if !strings.Contains(core+capture, snippet) {
			t.Fatalf("mmsg fragment source missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"int enter_mmsg_base01(",
		"int enter_mmsg_base2(",
		"int enter_mmsg_base3(",
		"ENTER_PROG_MMSG_BASE2",
		"ENTER_PROG_MMSG_BASE3",
	} {
		if !strings.Contains(dispatch, snippet) {
			t.Fatalf("mmsg enter dispatch missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"mmsg_bytes_progs",
		"__uint(max_entries, 4)",
		"MMSG_BYTES_PROG_BASE0",
		"MMSG_BYTES_PROG_BASE1",
		"MMSG_BYTES_PROG_BASE2",
		"MMSG_BYTES_PROG_BASE3",
	} {
		if !strings.Contains(runtimeABI, snippet) {
			t.Fatalf("mmsg bytes prog array missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"int enter_mmsg_bytes0(",
		"int enter_mmsg_bytes1(",
		"int enter_mmsg_bytes2(",
		"int enter_mmsg_bytes3(",
		"emit_mmsg_bytes_base0_enter_event_v2_direct(",
		"emit_mmsg_bytes_base3_enter_event_v2_direct(",
		"capture_mmsg_bytes_base0_enter_payloads_tlv_direct(",
		"capture_mmsg_bytes_base3_enter_payloads_tlv_direct(",
		"bpf_tail_call(ctx, &mmsg_bytes_progs, MMSG_BYTES_PROG_BASE0);",
	} {
		if !strings.Contains(combined+capture+dispatch, snippet) {
			t.Fatalf("mmsg bytes fragment source missing %q", snippet)
		}
	}
	if !strings.Contains(combined, "ENTER_PROG_MMSG_BASE01") {
		t.Fatal("mmsg enter dispatcher missing base01 tail-call target")
	}
	if !strings.Contains(combined, "bpf_tail_call(ctx, &enter_progs, ENTER_PROG_MMSG_BASE01);") {
		t.Fatal("mmsg enter handler does not start the merged fragment chain")
	}
	if strings.Contains(capture, "capture_mmsg_iovec_tlv_direct(\n        ptr,\n        payload_offset + payload_size") {
		t.Fatal("mmsg aggregate capture must not inline all iovec slots")
	}
}

func TestBPFMmsgBase01PreservesFragmentOrder(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/mmsg_enter_dispatch.h"))
	body, ok := bpfFunctionBody(source, "enter_mmsg_base01")
	if !ok {
		t.Fatal("mmsg enter dispatch missing merged base01 handler")
	}
	base0 := strings.Index(body, "emit_mmsg_base0_enter_event_v2_direct")
	base1 := strings.Index(body, "emit_mmsg_base1_enter_event_v2_direct")
	next := strings.Index(body, "ENTER_PROG_MMSG_BASE2")
	if base0 < 0 || base1 < 0 || next < 0 || base0 > base1 || base1 > next {
		t.Fatalf("mmsg enter base01 order is invalid: base0=%d base1=%d next=%d", base0, base1, next)
	}
	if strings.Contains(source, "int enter_mmsg_base0(") ||
		strings.Contains(source, "int enter_mmsg_base1(") {
		t.Fatal("mmsg enter base0/base1 handlers must be replaced by base01")
	}
}

func TestMmsgExitSlotHelperHasBoundedInterface(t *testing.T) {
	root := repoRootForTest(t)
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_capture_direct_event_v2.h"))
	body, ok := bpfFunctionBody(capture, "capture_recvmmsg_base_slot_exit_payloads_tlv_direct")
	if !ok {
		t.Fatal("mmsg capture source missing recvmmsg slot helper")
	}
	signature := strings.SplitN(body, "{", 2)[0]
	if strings.Count(signature, ",")+1 > 5 {
		t.Fatalf("recvmmsg slot helper has more than five parameters: %s", signature)
	}
	if !strings.Contains(body, "mmsg_iovec_arg_index_for_slot(slot)") {
		t.Fatal("recvmmsg slot helper must derive its synthetic arg index from slot")
	}
}

func TestBPFRecvmsgKretprobeChainSerializesFragments(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	attachSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_attach.go"))
	dispatchBody, ok := bpfFunctionBody(source, "trace_kretprobe_recvmsg_dispatch")
	if !ok {
		t.Fatal("strace.c missing recvmsg dispatcher body")
	}
	if strings.Contains(dispatchBody, "bpf_get_current_pid_tgid") ||
		strings.Contains(dispatchBody, "bpf_map_lookup_elem") ||
		strings.Contains(dispatchBody, "p->sys_id") {
		t.Fatal("recvmsg dispatcher must route without owning the pending identity gate")
	}

	for _, check := range []struct {
		name    string
		snippet string
	}{
		{"trace_kretprobe_recvmsg_dispatch", "bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_NAME);"},
		{"trace_kretprobe_recvmsg_name", "bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_CONTROL);"},
		{"trace_kretprobe_recvmsg_control", "bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_FINAL);"},
		{"trace_kretprobe_recvmsg_final", "consume_pending_syscall(pid, tid, p, 0);"},
	} {
		body, ok := bpfFunctionBody(source, check.name)
		if !ok {
			t.Fatalf("strace.c missing function body for %s", check.name)
		}
		if !strings.Contains(body, check.snippet) {
			t.Fatalf("%s missing recvmsg chain step %q", check.name, check.snippet)
		}
	}

	if !strings.Contains(attachSource, "a.objs.TraceKretprobeRecvmsgDispatch") {
		t.Fatal("bpf_attach.go does not attach the recvmsg dispatcher")
	}
	if strings.Contains(attachSource, "Kretprobe(symbol, a.objs.TraceKretprobeRecvmsgName") ||
		strings.Contains(attachSource, "Kretprobe(symbol, a.objs.TraceKretprobeRecvmsgControl") {
		t.Fatal("recvmsg fragment handlers must not be independently attached")
	}
}

func TestBPFRecvmmsgExitChainHasFinalFallback(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	for _, name := range []string{"exit_recvmmsg_base01", "exit_recvmmsg_base23"} {
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
	if strings.Contains(source, "int exit_recvmmsg_base2(") ||
		strings.Contains(source, "int exit_recvmmsg_base3(") {
		t.Fatal("recvmmsg base2/base3 handlers must be replaced by base23")
	}
}

func TestBPFRecvmmsgBase01PreservesFragmentOrder(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	body, ok := bpfFunctionBody(source, "exit_recvmmsg_base01")
	if !ok {
		t.Fatal("exit_dispatch.h missing merged recvmmsg base01 handler")
	}
	base0 := strings.Index(body, "emit_recvmmsg_base0_exit_fragment_event_v2_direct")
	base1 := strings.Index(body, "emit_recvmmsg_base1_exit_fragment_event_v2_direct")
	next := strings.Index(body, "EXIT_PROG_RECVMMSG_BASE23")
	if base0 < 0 || base1 < 0 || next < 0 || base0 > base1 || base1 > next {
		t.Fatalf("recvmmsg base01 chain order is invalid: base0=%d base1=%d next=%d", base0, base1, next)
	}
	if strings.Contains(source, "int exit_recvmmsg_base0(") ||
		strings.Contains(source, "int exit_recvmmsg_base1(") {
		t.Fatal("recvmmsg base0/base1 handlers must be replaced by base01")
	}
}

func TestBPFRecvmmsgBase23PreservesFragmentOrder(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	body, ok := bpfFunctionBody(source, "exit_recvmmsg_base23")
	if !ok {
		t.Fatal("exit_dispatch.h missing merged recvmmsg base23 handler")
	}
	base2 := strings.Index(body, "emit_recvmmsg_base2_exit_fragment_event_v2_direct")
	base3 := strings.Index(body, "emit_recvmmsg_base3_exit_fragment_event_v2_direct")
	final := strings.Index(body, "EXIT_PROG_MMSG_FINAL")
	if base2 < 0 || base3 < 0 || final < 0 || base2 > base3 || base3 > final {
		t.Fatalf("recvmmsg base23 order is invalid: base2=%d base3=%d final=%d", base2, base3, final)
	}
	if strings.Contains(source, "int exit_recvmmsg_base2(") ||
		strings.Contains(source, "int exit_recvmmsg_base3(") {
		t.Fatal("recvmmsg base2/base3 handlers must be replaced by base23")
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
