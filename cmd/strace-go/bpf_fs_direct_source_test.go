//go:build amd64 && linux

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFFSPayloadsUseDirectTLV(t *testing.T) {
	sources := loadFSDirectSources(t)
	assertFSDispatchSource(t, sources)
	assertFSDirectHeader(t, sources.fsDirect, sources.fsCapture, sources.fsEmit)
	assertMountSetattrDirectHeader(t, sources.mountSetattr, sources.pathCapture)
	assertNoLegacyFSCapture(t, sources.legacyCapture)
}

type fsDirectSources struct {
	combined      string
	timeDirect    string
	fsDirect      string
	fsCapture     string
	fsEmit        string
	mountSetattr  string
	pathCapture   string
	legacyCapture string
}

func loadFSDirectSources(t *testing.T) fsDirectSources {
	t.Helper()
	root := repoRootForTest(t)
	return fsDirectSources{
		combined:      readCombinedBPFSources(t),
		timeDirect:    readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h")),
		fsDirect:      readTextFile(t, filepath.Join(root, "bpf/syscall_fs_direct_event_v2.h")),
		fsCapture:     readTextFile(t, filepath.Join(root, "bpf/syscall_fs_capture_direct_event_v2.h")),
		fsEmit:        readTextFile(t, filepath.Join(root, "bpf/syscall_fs_emit_direct_event_v2.h")),
		mountSetattr:  readTextFile(t, filepath.Join(root, "bpf/syscall_mount_setattr_direct_event_v2.h")),
		pathCapture:   readTextFile(t, filepath.Join(root, "bpf/syscall_path_capture_direct_event_v2.h")),
		legacyCapture: legacyCaptureArtifactsForTest(t),
	}
}

func assertFSDispatchSource(t *testing.T, sources fsDirectSources) {
	t.Helper()
	for _, snippet := range []string{
		"#define SYS_GETDENTS 78",
		"#define SYS_MOUNT 165",
		"#define SYS_UMOUNT2 166",
		"#define SYS_GETDENTS64 217",
		"#define SYS_FSCONFIG 431",
		"#define SYS_MOUNT_SETATTR 442",
		"#define SYS_FILE_SETATTR 469",
		`#include "syscall_fs_direct_event_v2.h"`,
		"is_fs_enter_direct_syscall(sys_id)",
		"emit_fs_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);",
		"is_getdents_direct_syscall(p->sys_id) && ret_value > 0",
		"emit_getdents_exit_event_v2_direct(p, ret_value, duration);",
		"is_fs_direct_syscall(sys_id) ||",
	} {
		if !strings.Contains(sources.combined, snippet) && !strings.Contains(sources.timeDirect, snippet) &&
			!strings.Contains(sources.fsDirect, snippet) && !strings.Contains(sources.mountSetattr, snippet) {
			t.Fatalf("BPF source missing fs direct snippet %q", snippet)
		}
	}
}

func assertFSDirectHeader(t *testing.T, fsDirectHeader string, fsCapture string, fsEmit string) {
	t.Helper()
	fsSource := fsDirectHeader + "\n" + fsCapture + "\n" + fsEmit
	for _, snippet := range []string{
		"FS_DIRECT_MOUNT_STRING_MAX 512",
		"FS_DIRECT_MOUNT_TYPE_MAX 128",
		"FS_DIRECT_FSCONFIG_KEY_MAX 257",
		"FS_DIRECT_FSCONFIG_VALUE_MAX 4096",
		"FS_DIRECT_GETDENTS_BYTES_MAX 512",
		"FS_DIRECT_FSCONFIG_SET_BINARY 2",
		"is_fs_enter_direct_syscall(",
		"is_fs_direct_syscall(",
		"is_getdents_direct_syscall(",
		"capture_fs_string_tlv_direct(",
		"capture_fs_bytes_tlv_direct(",
		"capture_fs_enter_payload_tlv_direct(",
		"capture_getdents_bytes_tlv_direct(",
		"emit_getdents_exit_event_v2_direct(",
		"((u32)ctx->args[1]) == FS_DIRECT_FSCONFIG_SET_BINARY",
		"PAYLOAD_TLV_KIND_STRING",
		"PAYLOAD_TLV_KIND_BYTES",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"bpf_probe_read_user_str(payload_data, max_len",
		"bpf_probe_read_user(payload_data, copied_len",
		`#include "syscall_mount_setattr_direct_event_v2.h"`,
		"sys_id == SYS_MOUNT_SETATTR",
		"capture_mount_setattr_enter_payload_tlv_direct(",
		"sys_id == SYS_FILE_SETATTR",
		"capture_file_attr_tlvs_direct(",
	} {
		if !strings.Contains(fsSource, snippet) {
			t.Fatalf("fs direct header missing snippet %q", snippet)
		}
	}
}

func assertMountSetattrDirectHeader(t *testing.T, mountSetattrHeader string, pathCaptureHeader string) {
	t.Helper()
	for _, snippet := range []string{
		"MOUNT_SETATTR_BASE_SIZE 32",
		"MOUNT_SETATTR_EXTENSION_MAX 256",
		"FD_PATH_DIRECT_SECTION_MAX",
		"#include \"syscall_fd_path_direct_event_v2.h\"",
		"capture_fd_path_tlv_direct(",
		"ctx->args[1]",
		"ctx->args[3]",
		"ctx->args[4]",
		"PAYLOAD_TLV_KIND_STRUCT",
		"PAYLOAD_TLV_KIND_BYTES",
		"user_ptr + MOUNT_SETATTR_BASE_SIZE",
	} {
		if !strings.Contains(mountSetattrHeader, snippet) {
			t.Fatalf("mount_setattr direct header missing snippet %q", snippet)
		}
	}
	if !strings.Contains(pathCaptureHeader, "capture_path_only_tlv_direct(") {
		t.Fatal("mount_setattr direct header should use the dedicated path capture helper")
	}
	for _, snippet := range []string{
		"payload_offset + payload_size,\n            0,\n            (s32)ctx->args[0]",
		"payload_offset + payload_size,\n        1,\n        ctx->args[1]",
	} {
		if !strings.Contains(mountSetattrHeader, snippet) {
			t.Fatalf("mount_setattr direct header missing append offset %q", snippet)
		}
	}
}

func assertNoLegacyFSCapture(t *testing.T, legacyCaptureArtifacts string) {
	t.Helper()
	for _, legacyRule := range []string{
		"syscalls: [getdents]",
		"syscalls: [mount]",
		"syscalls: [umount2]",
		"syscalls: [getdents64]",
		"syscalls: [fsconfig]",
		"case 78: /* getdents */",
		"case 165: /* mount */",
		"case 166: /* umount2 */",
		"case 217: /* getdents64 */",
		"case 431: /* fsconfig */",
		"case 442: /* mount_setattr */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("fs syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}
