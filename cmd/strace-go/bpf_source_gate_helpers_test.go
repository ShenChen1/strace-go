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
	fdStateHeader          string
	legacyCaptureArtifacts string
}

func loadBPFSources(t *testing.T) bpfSourceGateSources {
	t.Helper()
	root := repoRootForTest(t)
	// Family capture logic moved out of strace.c into the tail call dispatch
	// headers; source gates assert against the combined text so the "uses
	// direct TLV" checks keep working after the dispatcher refactor.
	combinedStraceSource := readCombinedBPFSources(t) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h"))
	return bpfSourceGateSources{
		straceSource:           combinedStraceSource,
		legacyCaptureArtifacts: legacyCaptureArtifactsForTest(t),
		tlvHeader:              readTextFile(t, filepath.Join(root, "bpf/payload_tlv.h")),
		directHeader:           readDirectEventSources(t),
		fdArrayDirectHeader:    readTextFile(t, filepath.Join(root, "bpf/syscall_fd_array_direct_event_v2.h")),
		getcwdDirectHeader:     readTextFile(t, filepath.Join(root, "bpf/syscall_getcwd_direct_event_v2.h")),
		miscDirectHeader:       readTextFile(t, filepath.Join(root, "bpf/syscall_misc_struct_direct_event_v2.h")),
		statDirectHeader:       readTextFile(t, filepath.Join(root, "bpf/syscall_stat_direct_event_v2.h")),
		waitidDirectHeader:     readTextFile(t, filepath.Join(root, "bpf/syscall_waitid_direct_event_v2.h")),
		signalDirectHeader:     readTextFile(t, filepath.Join(root, "bpf/syscall_signal_direct_event_v2.h")),
		pathStatDirectHeader:   readTextFile(t, filepath.Join(root, "bpf/syscall_path_stat_direct_event_v2.h")),
		readlinkDirectHeader: readTextFile(t, filepath.Join(root, "bpf/syscall_readlink_direct_event_v2.h")) +
			"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_readlink_capture_direct_event_v2.h")) +
			"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_readlink_emit_direct_event_v2.h")),
		timeDirectHeader: readTimeDirectEventSources(t),
		fdStateHeader:    readTextFile(t, filepath.Join(root, "bpf/syscall_fd_state_direct_event_v2.h")),
	}
}

func readDirectEventSources(t *testing.T) string {
	t.Helper()
	root := repoRootForTest(t)
	return readTextFile(t, filepath.Join(root, "bpf/syscall_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_event_core_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_payload_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_exec_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_payload_emit_direct_event_v2.h"))
}

func readMsgDirectEventSources(t *testing.T) string {
	t.Helper()
	root := repoRootForTest(t)
	return readTextFile(t, filepath.Join(root, "bpf/syscall_iovec_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_msg_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_msg_core_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_msg_control_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_msg_capture_direct_event_v2.h")) +
		"\n" + readMmsgCaptureSources(t) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_msg_enter_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_bytes_enter_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_msg_exit_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_msg_recv_exit_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_exit_direct_event_v2.h"))
}

func readMmsgCaptureSources(t *testing.T) string {
	t.Helper()
	root := repoRootForTest(t)
	return readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_struct_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_mmsg_bytes_capture_direct_event_v2.h"))
}

func readTimeDirectEventSources(t *testing.T) string {
	t.Helper()
	root := repoRootForTest(t)
	return readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_time_emit_direct_event_v2.h"))
}

func readAioDirectEventSources(t *testing.T) string {
	t.Helper()
	root := repoRootForTest(t)
	return readTextFile(t, filepath.Join(root, "bpf/syscall_aio_getevents_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_aio_getevents_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_aio_getevents_emit_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_aio_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_aio_core_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_aio_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_aio_cancel_capture_direct_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_aio_emit_direct_event_v2.h"))
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

// readCombinedBPFSources returns the BPF translation unit sources in include
// order so source gates assert behavior without coupling it to one file.
// Family capture and routing logic lives in the dispatch headers after the
// dispatcher refactor, so source gates that assert "uses direct TLV" check all
// of them.
func readCombinedBPFSources(t *testing.T) string {
	t.Helper()
	root := repoRootForTest(t)
	return readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/syscall_numbers_generated.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/runtime_stats.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/lifecycle_event_v2.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/pending_state.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/lifecycle_state.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/lifecycle_dispatch.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/strace.c")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/enter_runtime.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/enter_dispatch.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/enter_fragment_dispatch.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/enter_router.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/mmsg_enter_dispatch.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/exit_dispatch.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/recvmsg_kretprobe_dispatch.h")) +
		"\n" + readTextFile(t, filepath.Join(root, "bpf/exit_router.h"))
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

func TestBPFRuntimeSourceHasNoDebugPrintk(t *testing.T) {
	source := readCombinedBPFSources(t)
	for _, token := range []string{
		"bpf_printk(",
		"bpf_trace_printk(",
		"trace_printk(",
	} {
		if strings.Contains(source, token) {
			t.Fatalf("BPF runtime source contains debug printk token %q", token)
		}
	}
}
