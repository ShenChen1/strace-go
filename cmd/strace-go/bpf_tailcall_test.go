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
	for i := 1; i <= enterProgQuota; i++ {
		if !seen[uint32(i)] {
			t.Fatalf("enter prog array missing index %d", i)
		}
	}
	if len(entries) != enterProgQuota {
		t.Fatalf("enter prog array entries = %d, want %d", len(entries), enterProgQuota)
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
	for i := 0; i <= exitProgMountQuery; i++ {
		if !seen[uint32(i)] {
			t.Fatalf("exit prog array missing index %d", i)
		}
	}
	if len(entries) != exitProgMountQuery+1 {
		t.Fatalf("exit prog array entries = %d, want %d", len(entries), exitProgMountQuery+1)
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
	source := readCombinedBPFSources(t)
	pairs := map[string]uint32{
		"RECVMSG_PROG_NAME":    recvmsgProgName,
		"RECVMSG_PROG_CONTROL": recvmsgProgControl,
		"RECVMSG_PROG_FINAL":   recvmsgProgFinal,
	}
	for name, value := range pairs {
		if !strings.Contains(source, fmt.Sprintf("%s = %d", name, value)) {
			t.Fatalf("strace.c missing %s = %d", name, value)
		}
	}
}

func TestEnterProgIndicesMatchDispatchHeader(t *testing.T) {
	root := repoRootForTest(t)
	header := readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h"))
	pairs := map[string]uint32{
		"ENTER_PROG_TERMINATING":       enterProgTerminating,
		"ENTER_PROG_IOVEC":             enterProgIovec,
		"ENTER_PROG_MSG":               enterProgMsg,
		"ENTER_PROG_MMSG":              enterProgMmsg,
		"ENTER_PROG_AIO":               enterProgAio,
		"ENTER_PROG_NO_PAYLOAD_DIRECT": enterProgNoPayload,
		"ENTER_PROG_PAYLOAD_DIRECT":    enterProgPayload,
		"ENTER_PROG_IOVEC_BASE":        enterProgIovecBase,
		"ENTER_PROG_AIO_BUF":           enterProgAioBuf,
		"ENTER_PROG_QUOTA":             enterProgQuota,
	}
	for name, val := range pairs {
		if !strings.Contains(header, fmt.Sprintf("%s = %d", name, val)) {
			t.Fatalf("enter_dispatch.h missing %s = %d", name, val)
		}
	}
}

func TestExitProgIndicesMatchDispatchHeader(t *testing.T) {
	root := repoRootForTest(t)
	header := readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	pairs := map[string]uint32{
		"EXIT_PROG_GENERIC":        exitProgGeneric,
		"EXIT_PROG_IOVEC_BASE":     exitProgIovecBase,
		"EXIT_PROG_MSG":            exitProgMsg,
		"EXIT_PROG_MMSG_FINAL":     exitProgMmsgFinal,
		"EXIT_PROG_RECVMMSG_BASE0": exitProgRecvmmsgBase0,
		"EXIT_PROG_RECVMMSG_BASE1": exitProgRecvmmsgBase1,
		"EXIT_PROG_QUOTA":          exitProgQuota,
		"EXIT_PROG_MOUNT_QUERY":    exitProgMountQuery,
	}
	for name, val := range pairs {
		if !strings.Contains(header, fmt.Sprintf("%s = %d", name, val)) {
			t.Fatalf("exit_dispatch.h missing %s = %d", name, val)
		}
	}
}

func TestBuildRuntimeConfigEnablesFDStateForPathRendering(t *testing.T) {
	plain, err := buildRuntimeConfig(cli.ParseArgs([]string{"/bin/true"}), &bpfObjects{})
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
		cfg, err := buildRuntimeConfig(cli.ParseArgs(args), &bpfObjects{})
		if err != nil {
			t.Fatalf("buildRuntimeConfig(%v): %v", args, err)
		}
		if cfg&bpfConfigFdState == 0 {
			t.Fatalf("config %v missing FD_STATE bit: %#x", args, cfg)
		}
	}
}
