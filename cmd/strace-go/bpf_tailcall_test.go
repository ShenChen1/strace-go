package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestEnterProgArrayEntriesComplete(t *testing.T) {
	entries := enterProgArrayEntries(&bpfObjects{})
	seen := make(map[uint32]bool)
	for _, entry := range entries {
		if seen[entry.index] {
			t.Fatalf("duplicate enter prog array index %d", entry.index)
		}
		seen[entry.index] = true
	}
	// Every dispatcher index from enter_dispatch.h must have a slot; missing
	// slots silently drop that syscall family.
	for i := 1; i <= enterProgBpfTracingMulti; i++ {
		if !seen[uint32(i)] {
			t.Fatalf("enter prog array missing index %d", i)
		}
	}
	if len(entries) != enterProgBpfTracingMulti {
		t.Fatalf("enter prog array entries = %d, want %d", len(entries), enterProgBpfTracingMulti)
	}
}

func TestMmsgBytesProgArrayEntriesComplete(t *testing.T) {
	entries := mmsgBytesProgArrayEntries(&bpfObjects{})
	seen := make(map[uint32]bool)
	for _, entry := range entries {
		if seen[entry.index] {
			t.Fatalf("duplicate mmsg bytes prog array index %d", entry.index)
		}
		seen[entry.index] = true
	}
	for i := uint32(mmsgBytesProgBase0); i <= mmsgBytesProgBase3; i++ {
		if !seen[i] {
			t.Fatalf("mmsg bytes prog array missing index %d", i)
		}
	}
	if len(entries) != mmsgBytesProgBase3+1 {
		t.Fatalf("mmsg bytes prog array entries = %d, want %d", len(entries), mmsgBytesProgBase3+1)
	}
}

func TestMmsgBytesProgIndicesMatchBPFSource(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/capture_manifest_generated.h"))
	pairs := map[string]uint32{
		"MMSG_BYTES_PROG_BASE0": mmsgBytesProgBase0,
		"MMSG_BYTES_PROG_BASE1": mmsgBytesProgBase1,
		"MMSG_BYTES_PROG_BASE2": mmsgBytesProgBase2,
		"MMSG_BYTES_PROG_BASE3": mmsgBytesProgBase3,
	}
	for name, value := range pairs {
		if !strings.Contains(source, fmt.Sprintf("%s = %d", name, value)) {
			t.Fatalf("capture manifest missing %s = %d", name, value)
		}
	}
}

func TestExitProgArrayEntriesComplete(t *testing.T) {
	entries := exitProgArrayEntries(&bpfObjects{})
	seen := make(map[uint32]bool)
	for _, entry := range entries {
		if seen[entry.index] {
			t.Fatalf("duplicate exit prog array index %d", entry.index)
		}
		seen[entry.index] = true
	}
	for i := uint32(exitProgGeneric); i <= exitProgPIDNS; i++ {
		if !seen[i] {
			t.Fatalf("exit prog array missing index %d", i)
		}
	}
	if len(entries) != exitProgPIDNS+1 {
		t.Fatalf("exit prog array entries = %d, want %d", len(entries), exitProgPIDNS+1)
	}
}

func TestRecvmsgProgArrayEntriesComplete(t *testing.T) {
	entries := recvmsgProgArrayEntries(&bpfObjects{})
	seen := make(map[uint32]bool)
	for _, entry := range entries {
		if seen[entry.index] {
			t.Fatalf("duplicate recvmsg prog array index %d", entry.index)
		}
		seen[entry.index] = true
	}
	for i := uint32(recvmsgProgName); i <= recvmsgProgFinal; i++ {
		if !seen[i] {
			t.Fatalf("recvmsg prog array missing index %d", i)
		}
	}
	if len(entries) != recvmsgProgFinal+1 {
		t.Fatalf("recvmsg prog array entries = %d, want %d", len(entries), recvmsgProgFinal+1)
	}
}

func TestRecvmsgProgIndicesMatchBPFSource(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "bpf/capture_manifest_generated.h"))
	pairs := map[string]uint32{
		"RECVMSG_PROG_NAME":    recvmsgProgName,
		"RECVMSG_PROG_CONTROL": recvmsgProgControl,
		"RECVMSG_PROG_FINAL":   recvmsgProgFinal,
	}
	for name, value := range pairs {
		if !strings.Contains(source, fmt.Sprintf("%s = %d", name, value)) {
			t.Fatalf("capture manifest missing %s = %d", name, value)
		}
	}
}

func TestEnterProgIndicesMatchDispatchHeader(t *testing.T) {
	root := repoRootForTest(t)
	header := readTextFile(t, filepath.Join(root, "bpf/capture_manifest_generated.h"))
	pairs := map[string]uint32{
		"ENTER_PROG_TERMINATING":         enterProgTerminating,
		"ENTER_PROG_BPF_UPROBE_MULTI":    enterProgBpfUprobeMulti,
		"ENTER_PROG_BPF_TRACING_MULTI":   enterProgBpfTracingMulti,
		"ENTER_PROG_BPF_PROG_LOAD":       enterProgBpfProgLoad,
		"ENTER_PROG_BPF_PROG_LOAD_DEBUG": enterProgBpfProgLoadDebug,
		"ENTER_PROG_IOVEC":               enterProgIovec,
		"ENTER_PROG_MSG":                 enterProgMsg,
		"ENTER_PROG_MMSG":                enterProgMmsg,
		"ENTER_PROG_AIO":                 enterProgAio,
		"ENTER_PROG_NO_PAYLOAD_DIRECT":   enterProgNoPayload,
		"ENTER_PROG_PAYLOAD_DIRECT":      enterProgPayload,
		"ENTER_PROG_IOVEC_BASE":          enterProgIovecBase,
		"ENTER_PROG_MMSG_BASE01":         enterProgMmsgB01,
		"ENTER_PROG_MMSG_BASE2":          enterProgMmsgB2,
		"ENTER_PROG_MMSG_BASE3":          enterProgMmsgB3,
		"ENTER_PROG_AIO_BUF":             enterProgAioBuf,
		"ENTER_PROG_QUOTA":               enterProgQuota,
		"ENTER_PROG_MOUNT_PATH":          enterProgMountPath,
		"ENTER_PROG_NESTED_FD_PATH0":     enterProgNestedFDPath0,
		"ENTER_PROG_NESTED_FD_PATH1":     enterProgNestedFDPath1,
		"ENTER_PROG_NESTED_FD_PATH2":     enterProgNestedFDPath2,
		"ENTER_PROG_NESTED_FD_PATH3":     enterProgNestedFDPath3,
	}
	for name, val := range pairs {
		if !strings.Contains(header, fmt.Sprintf("%s = %d", name, val)) {
			t.Fatalf("capture manifest missing %s = %d", name, val)
		}
	}
	if !strings.Contains(header, "STRACE_GO_ENTER_PROG_ARRAY_MAX_ENTRIES 55") {
		t.Fatal("capture manifest must include the enter prog array capacity")
	}
}

func TestExitProgIndicesMatchDispatchHeader(t *testing.T) {
	root := repoRootForTest(t)
	header := readTextFile(t, filepath.Join(root, "bpf/capture_manifest_generated.h"))
	pairs := map[string]uint32{
		"EXIT_PROG_GENERIC":         exitProgGeneric,
		"EXIT_PROG_IOVEC_BASE":      exitProgIovecBase,
		"EXIT_PROG_MSG":             exitProgMsg,
		"EXIT_PROG_MMSG_FINAL":      exitProgMmsgFinal,
		"EXIT_PROG_RECVMMSG_BASE01": exitProgRecvmmsgBase01,
		"EXIT_PROG_RECVMMSG_BASE23": exitProgRecvmmsgBase23,
		"EXIT_PROG_QUOTA":           exitProgQuota,
		"EXIT_PROG_MOUNT_QUERY":     exitProgMountQuery,
		"EXIT_PROG_PATH":            exitProgPath,
		"EXIT_PROG_FD_TIME":         exitProgFDTime,
		"EXIT_PROG_STRUCT":          exitProgStruct,
		"EXIT_PROG_ASYNC":           exitProgAsync,
		"EXIT_PROG_IO":              exitProgIO,
		"EXIT_PROG_CONTROL":         exitProgControl,
		"EXIT_PROG_NESTED_FD_PATH0": exitProgNestedFDPath0,
		"EXIT_PROG_NESTED_FD_PATH1": exitProgNestedFDPath1,
		"EXIT_PROG_NESTED_FD_PATH2": exitProgNestedFDPath2,
		"EXIT_PROG_NESTED_FD_PATH3": exitProgNestedFDPath3,
		"EXIT_PROG_NAMESPACE":       exitProgNamespace,
		"EXIT_PROG_PID_NAMESPACE":   exitProgPIDNS,
	}
	for name, val := range pairs {
		if !strings.Contains(header, fmt.Sprintf("%s = %d", name, val)) {
			t.Fatalf("capture manifest missing %s = %d", name, val)
		}
	}
	if !strings.Contains(header, "STRACE_GO_EXIT_PROG_ARRAY_MAX_ENTRIES 20") {
		t.Fatal("capture manifest must include the exit prog array capacity")
	}
}

func TestBuildRuntimeConfigEnablesFDStateForPathRendering(t *testing.T) {
	plain, err := buildRuntimeConfig(newTraceBPFConfig(cli.ParseArgs([]string{"--event-format=reader", "/bin/true"})), &bpfObjects{})
	if err != nil {
		t.Fatalf("buildRuntimeConfig(plain): %v", err)
	}
	if plain&bpfConfigFdState != 0 {
		t.Fatalf("plain config has FD_STATE bit: %#x", plain)
	}

	for _, args := range [][]string{
		{"-y", "/bin/true"},
		{"-yy", "/bin/true"},
		{"-P", "/tmp", "/bin/true"},
	} {
		cfg, err := buildRuntimeConfig(newTraceBPFConfig(cli.ParseArgs(args)), &bpfObjects{})
		if err != nil {
			t.Fatalf("buildRuntimeConfig(%v): %v", args, err)
		}
		if cfg&bpfConfigFdState == 0 {
			t.Fatalf("config %v missing FD_STATE bit: %#x", args, cfg)
		}
	}
}
