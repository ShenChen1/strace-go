package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFPIDFDOpenEmitsFDStateSnapshot(t *testing.T) {
	root := repoRootForTest(t)
	runtimeStats := readTextFile(t, filepath.Join(root, "bpf/runtime_stats.h"))
	fdState := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_state_direct_event_v2.h"))
	routes := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_capture_manifest_generated.go"))

	if !strings.Contains(runtimeStats, "case SYS_PIDFD_OPEN:") {
		t.Fatal("background FD state tracking omits pidfd_open")
	}
	if !strings.Contains(fdState, "SYS_PIDFD_OPEN") {
		t.Fatal("FD state exit emitter omits pidfd_open")
	}
	for _, line := range strings.Split(routes, "\n") {
		if strings.Contains(line, `"pidfd_open":`) &&
			strings.Contains(line, "exitSlot: exitProgFDTime") {
			return
		}
	}
	t.Fatal("capture manifest does not route pidfd_open through exit_fd_time")
}
