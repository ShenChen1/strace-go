package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bpfSourceGateSources holds BPF sources shared by the direct-TLV source gates.
type bpfSourceGateSources struct {
	straceSource           string
	tlvHeader              string
	directHeader           string
	fdArrayDirectHeader    string
	getcwdDirectHeader     string
	miscDirectHeader       string
	statDirectHeader       string
	waitidDirectHeader     string
	signalDirectHeader     string
	pathStatDirectHeader   string
	readlinkDirectHeader   string
	timeDirectHeader       string
	legacyCaptureArtifacts string
}

func loadBPFSources(t *testing.T) bpfSourceGateSources {
	t.Helper()
	root := repoRootForTest(t)
	return bpfSourceGateSources{
		straceSource:           readTextFile(t, filepath.Join(root, "bpf/strace.c")),
		legacyCaptureArtifacts: legacyCaptureArtifactsForTest(t),
		tlvHeader:              readTextFile(t, filepath.Join(root, "bpf/payload_tlv.h")),
		directHeader:           readTextFile(t, filepath.Join(root, "bpf/syscall_direct_event_v2.h")),
		fdArrayDirectHeader:    readTextFile(t, filepath.Join(root, "bpf/syscall_fd_array_direct_event_v2.h")),
		getcwdDirectHeader:     readTextFile(t, filepath.Join(root, "bpf/syscall_getcwd_direct_event_v2.h")),
		miscDirectHeader:       readTextFile(t, filepath.Join(root, "bpf/syscall_misc_struct_direct_event_v2.h")),
		statDirectHeader:       readTextFile(t, filepath.Join(root, "bpf/syscall_stat_direct_event_v2.h")),
		waitidDirectHeader:     readTextFile(t, filepath.Join(root, "bpf/syscall_waitid_direct_event_v2.h")),
		signalDirectHeader:     readTextFile(t, filepath.Join(root, "bpf/syscall_signal_direct_event_v2.h")),
		pathStatDirectHeader:   readTextFile(t, filepath.Join(root, "bpf/syscall_path_stat_direct_event_v2.h")),
		readlinkDirectHeader:   readTextFile(t, filepath.Join(root, "bpf/syscall_readlink_direct_event_v2.h")),
		timeDirectHeader:       readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h")),
	}
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func legacyCaptureArtifactsForTest(t *testing.T) string {
	t.Helper()
	root := repoRootForTest(t)
	var out strings.Builder
	for _, rel := range []string{
		"cmd/generate-syscalls/capture_rules.yaml",
		"bpf/syscall_capture.h",
	} {
		path := filepath.Join(root, rel)
		data, err := os.ReadFile(path)
		if err == nil {
			out.Write(data)
			out.WriteByte('\n')
			continue
		}
		if !os.IsNotExist(err) {
			t.Fatalf("read legacy capture artifact %s: %v", path, err)
		}
	}
	return out.String()
}

func TestLegacyCaptureArtifactsAreRemoved(t *testing.T) {
	root := repoRootForTest(t)
	for _, rel := range []string{
		"cmd/generate-syscalls/capture_rules.yaml",
		"bpf/syscall_capture.h",
	} {
		path := filepath.Join(root, rel)
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("legacy fixed-window capture artifact still exists: %s", rel)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
}
