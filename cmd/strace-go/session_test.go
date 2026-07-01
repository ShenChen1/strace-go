package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestIsPassThroughFDTarget(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{target: "/tmp/output", want: true},
		{target: "/dev/full", want: true},
		{target: "/proc/123/fd/4", want: false},
		{target: "/sys/kernel/debug", want: false},
		{target: "pipe:[123]", want: false},
		{target: "socket:[123]", want: false},
		{target: "anon_inode:bpf-link", want: false},
		{target: "relative/path", want: false},
	}

	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			if got := isPassThroughFDTarget(test.target); got != test.want {
				t.Fatalf("isPassThroughFDTarget(%q) = %v, want %v", test.target, got, test.want)
			}
		})
	}
}

func TestNewTraceCommandDoesNotConfigurePtrace(t *testing.T) {
	cmd := newTraceCommand(&cli.Options{CmdArgs: []string{"/bin/true"}}, nil)
	if cmd.SysProcAttr != nil {
		t.Fatalf("SysProcAttr = %#v, want nil so tracing stays eBPF-only", cmd.SysProcAttr)
	}
}

func TestProductSourceHasNoRuntimePtraceOrProcmemDependency(t *testing.T) {
	forbidden := []string{
		"syscall.Ptrace",
		"unix.Ptrace",
		"PtracePeek",
		"PtraceAttach",
		"PtraceCont",
		"PtraceSetOptions",
		"PtraceSyscall",
		"ProcessVMReadv",
		"process_vm_readv(",
		"MemReader",
		"ReadRobust(",
		"\"strace-go/pkg/procmem\"",
		"procmem.",
		"/proc/%d/mem",
	}
	for _, path := range productGoFiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(data)
		for _, token := range forbidden {
			if strings.Contains(src, token) {
				t.Fatalf("%s contains forbidden runtime memory dependency token %q", path, token)
			}
		}
	}
}

func TestPendingSyscallsMapUsesCompactValue(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf() failed: %v", err)
	}

	if _, ok := spec.Maps["events_map"]; ok {
		t.Fatal("events_map should not remain as the syscall pending state map")
	}
	pending := spec.Maps["pending_syscalls"]
	if pending == nil {
		t.Fatal("pending_syscalls map missing from BPF object")
	}
	if pending.ValueSize > 128 {
		t.Fatalf("pending_syscalls value size = %d, want <= 128 bytes", pending.ValueSize)
	}
}

func TestExitStatusFollowsActualTraceeExit(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}

	session.queueExitStatus(101, "exited\n")
	if output.Len() != 0 {
		t.Fatalf("exit status printed before wait exit: %q", output.String())
	}
	session.markTraceeExited(101)
	if output.String() != "exited\n" {
		t.Fatalf("exit status output = %q", output.String())
	}
}

func TestExitStatusHandlesWaitBeforeRingEvent(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}

	session.markTraceeExited(101)
	session.queueExitStatus(101, "exited\n")
	if output.String() != "exited\n" {
		t.Fatalf("exit status output = %q", output.String())
	}
}

func TestDiscardExitStatusForSupersededLeader(t *testing.T) {
	var output bytes.Buffer
	session := &traceSession{outWriter: &output}

	session.queueExitStatus(101, "wrong exit\n")
	session.markTraceeExited(102)
	session.discardExitStatus(101)
	session.discardExitStatus(102)
	session.queueExitStatus(102, "final exit\n")
	if output.Len() != 0 {
		t.Fatalf("discarded exit status output = %q", output.String())
	}
}

func TestShouldQueueExitStatusSkipsExplicitAttachPid(t *testing.T) {
	session := &traceSession{
		cmd:  fakeStartedCommand(),
		opts: &cli.Options{AttachPids: []int{202}},
	}

	if session.shouldQueueExitStatus(202) {
		t.Fatal("explicit attach pid exit status should not wait for command exit")
	}
	if !session.shouldQueueExitStatus(303) {
		t.Fatal("non-attached command tracee exit status should wait for command exit")
	}
}

func fakeStartedCommand() *exec.Cmd {
	return &exec.Cmd{}
}

func productGoFiles(t *testing.T) []string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	dirs := []string{
		filepath.Join(root, "cmd/strace-go"),
		filepath.Join(root, "pkg/cli"),
		filepath.Join(root, "pkg/event"),
		filepath.Join(root, "pkg/format"),
		filepath.Join(root, "pkg/handler"),
		filepath.Join(root, "pkg/stacktrace"),
	}
	var files []string
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") ||
				strings.HasSuffix(name, "_test.go") ||
				strings.HasPrefix(name, "bpf_bpf") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return files
}
