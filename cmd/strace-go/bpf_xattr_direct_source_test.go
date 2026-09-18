//go:build amd64 && linux

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFXattrPayloadsUseDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	xattrDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_xattr_direct_event_v2.h"))
	xattrCaptureHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_xattr_capture_direct_event_v2.h"))
	xattrEmitHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_xattr_emit_direct_event_v2.h"))
	xattrDirectSources := xattrDirectHeader + "\n" + xattrCaptureHeader + "\n" + xattrEmitHeader

	for _, snippet := range []string{
		"#define SYS_SETXATTR 188",
		"#define SYS_FREMOVEXATTR 199",
		`#include "syscall_xattr_direct_event_v2.h"`,
		"is_xattr_direct_syscall(sys_id)",
		"emit_xattr_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);",
		"is_xattr_direct_syscall(sys_id) ||",
		"emit_xattr_get_exit_event_v2_direct(p, ret_value, duration);",
		"emit_xattr_list_exit_event_v2_direct(p, ret_value, duration);",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(timeDirectHeader, snippet) && !strings.Contains(xattrDirectSources, snippet) {
			t.Fatalf("BPF source missing xattr direct snippet %q", snippet)
		}
	}

	for _, snippet := range []string{
		"XATTR_DIRECT_PATH_MAX 512",
		"XATTR_DIRECT_NAME_MAX 256",
		"XATTR_DIRECT_VALUE_MAX 256",
		"is_xattr_set_direct_syscall(",
		"is_xattr_get_direct_syscall(",
		"is_xattr_list_direct_syscall(",
		"capture_xattr_string_tlv_direct(",
		"capture_xattr_bytes_tlv_direct(",
		"PAYLOAD_TLV_KIND_STRING",
		"PAYLOAD_TLV_KIND_BYTES",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user_str(payload_data, max_len",
		"bpf_probe_read_user(payload_data, copied_len",
	} {
		if !strings.Contains(xattrDirectSources, snippet) {
			t.Fatalf("xattr direct header missing snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [setxattr, lsetxattr]",
		"syscalls: [fsetxattr]",
		"syscalls: [getxattr, lgetxattr]",
		"syscalls: [fgetxattr]",
		"syscalls: [removexattr, lremovexattr]",
		"syscalls: [fremovexattr]",
		"syscalls: [listxattr, llistxattr]",
		"syscalls: [flistxattr]",
		"case 188: /* setxattr */",
		"case 193: /* fgetxattr */",
		"case 196: /* flistxattr */",
		"case 199: /* fremovexattr */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("xattr syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
