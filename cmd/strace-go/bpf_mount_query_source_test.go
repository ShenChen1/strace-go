package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFMountQueryUsesVersionedDirectTLV(t *testing.T) {
	root := repoRootForTest(t)
	source := readCombinedBPFSources(t)
	fsHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_fs_direct_event_v2.h"))
	header := readTextFile(t, filepath.Join(root, "bpf/syscall_mount_query_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_mount_query_capture_direct_event_v2.h"))
	emit := readTextFile(t, filepath.Join(root, "bpf/syscall_mount_query_emit_direct_event_v2.h"))
	dispatch := readTextFile(t, filepath.Join(root, "bpf/mount_query_dispatch.h"))

	for _, snippet := range []string{
		"#define SYS_STATMOUNT 457", "#define SYS_LISTMOUNT 458",
		"ENTER_PROG_FS", "EXIT_PROG_MOUNT_QUERY = 7",
		`#include "mount_query_dispatch.h"`,
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("BPF source missing mount query snippet %q", snippet)
		}
	}
	for _, snippet := range []string{
		`#include "syscall_mount_query_direct_event_v2.h"`,
		"is_mount_query_direct_syscall(sys_id)",
	} {
		if !strings.Contains(fsHeader, snippet) {
			t.Fatalf("filesystem direct event facade missing %q", snippet)
		}
	}

	for _, snippet := range []string{
		"MNT_ID_REQ_SIZE_FIELD_SIZE 4", "MNT_ID_REQ_SIZE_VER0 24",
		"MNT_ID_REQ_SIZE_VER1 32", "MNT_ID_REQ_EXTENSION_MAX 256",
		"STATMOUNT_FIXED_SIZE 512", "STATMOUNT_STRING_MAX 4096",
		"LISTMOUNT_ID_MAX 32",
	} {
		if !strings.Contains(header, snippet) {
			t.Fatalf("mount query header missing snippet %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_mnt_id_req_enter_tlv_direct(",
		"capture_statmount_exit_tlv_direct(",
		"capture_listmount_ids_tlv_direct(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("mount query capture header missing snippet %q", snippet)
		}
	}
	if !strings.Contains(emit, "emit_mount_query_exit_event_v2_direct(") {
		t.Fatal("mount query emit header missing exit emitter")
	}

	for _, snippet := range []string{
		"int exit_mount_query(", "emit_mount_query_exit_event_v2_direct(",
		"consume_pending_syscall(",
	} {
		if !strings.Contains(dispatch, snippet) {
			t.Fatalf("mount query dispatch missing snippet %q", snippet)
		}
	}
}
