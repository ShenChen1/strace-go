package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFNetworkPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	networkDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_network_direct_event_v2.h"))
	networkCaptureHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_network_capture_direct_event_v2.h"))
	networkEmitHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_network_emit_direct_event_v2.h"))
	networkExitFacade := readTextFile(t, filepath.Join(root, "bpf/syscall_network_direct_exit_event_v2.h"))
	networkExitCaptureHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_network_exit_capture_direct_event_v2.h"))
	networkExitEmitHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_network_exit_emit_direct_event_v2.h"))
	networkEnterHeader := networkDirectHeader + "\n" + networkCaptureHeader + "\n" + networkEmitHeader
	networkExitHeader := networkExitFacade + "\n" + networkExitCaptureHeader + "\n" + networkExitEmitHeader

	for _, snippet := range []string{
		"#define SYS_CONNECT 42",
		"#define SYS_RECVFROM 45",
		"#define SYS_ACCEPT4 288",
		"#define SYS_SETSOCKOPT 54",
		"#define SYS_GETSOCKOPT 55",
		`#include "syscall_network_direct_event_v2.h"`,
		"is_network_direct_syscall(sys_id)",
		"struct network_direct_args network_args = {};",
		"emit_network_enter_event_v2_direct(pid, tid, sys_id, &network_args, enter_time, &sockaddr_len);",
		"save_pending_network_syscall_args(tid, pid, sys_id, &network_args, enter_time, stack_id, sockaddr_len);",
		"is_network_direct_syscall(sys_id) ||",
		"emit_network_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) {
			t.Fatalf("BPF source missing network direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"is_network_direct_syscall(",
		"is_network_sockopt_direct_syscall(",
		"*sockaddr_len = optlen;",
		"save_pending_network_syscall_args(",
		"p.aux0 = sockaddr_len;",
		"init_network_enter_event_v2_from_args(&body, args, payload_size);",
	} {
		if !strings.Contains(networkEnterHeader, snippet) && !strings.Contains(networkExitHeader, snippet) {
			t.Fatalf("network direct header missing snippet %q", snippet)
		}
	}
	for _, snippet := range []string{
		"NETWORK_DIRECT_BYTES_MAX 512",
		"NETWORK_DIRECT_SOCKADDR_MAX 128",
		"NETWORK_DIRECT_SOCKLEN_SIZE 4",
		"capture_network_tlv_direct(",
		"capture_network_socklen_tlv_direct(",
		"network_direct_sockopt_len(",
		"network_direct_sockopt_payload_len(",
		"network_direct_sockopt_fixed_int(",
		"network_direct_sockopt_membership_array(",
		"return length & ~3U;",
		"return option != 9;",
		"option == 84",
		"PAYLOAD_TLV_KIND_BYTES",
		"bpf_probe_read_user(",
	} {
		if !strings.Contains(networkCaptureHeader, snippet) {
			t.Fatalf("network capture header missing snippet %q", snippet)
		}
	}
	for _, snippet := range []string{
		"PAYLOAD_TLV_KIND_STRUCT",
		"capture_network_getsockopt_exit_tlv_direct(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);",
	} {
		if !strings.Contains(networkExitHeader, snippet) {
			t.Fatalf("network exit header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [connect, bind]",
		"syscalls: [sendto]",
		"syscalls: [recvfrom]",
		"syscalls: [accept, accept4, getsockname, getpeername]",
		"case 42: /* connect */",
		"case 43: /* accept */",
		"case 44: /* sendto */",
		"case 45: /* recvfrom */",
		"case 49: /* bind */",
		"case 51: /* getsockname */",
		"case 52: /* getpeername */",
		"case 288: /* accept4 */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("network syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
