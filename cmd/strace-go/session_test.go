package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"strace-go/pkg/cli"
)

func TestIsPassThroughFDMode(t *testing.T) {
	tests := []struct {
		name string
		mode uint32
		want bool
	}{
		{name: "regular", mode: unix.S_IFREG, want: true},
		{name: "directory", mode: unix.S_IFDIR, want: true},
		{name: "character device", mode: unix.S_IFCHR, want: true},
		{name: "block device", mode: unix.S_IFBLK, want: true},
		{name: "fifo", mode: unix.S_IFIFO, want: true},
		{name: "socket", mode: unix.S_IFSOCK, want: false},
		{name: "symlink", mode: unix.S_IFLNK, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isPassThroughFDMode(test.mode); got != test.want {
				t.Fatalf("isPassThroughFDMode(%#o) = %v, want %v", test.mode, got, test.want)
			}
		})
	}
}

func TestNewTraceCommandDoesNotConfigurePtrace(t *testing.T) {
	cmd := newTraceCommand(traceCommandSpec{args: []string{"/bin/true"}}, nil)
	if cmd.SysProcAttr != nil {
		t.Fatalf("SysProcAttr = %#v, want nil so tracing stays eBPF-only", cmd.SysProcAttr)
	}
}

func TestStartTraceCmdRejectsUnavailableBPF(t *testing.T) {
	bootstrap := &traceTargetBootstrap{}
	_, _, _, err := bootstrap.startTraceCmd(traceCommandSpec{args: []string{"/definitely/missing/strace-go-target"}})
	if err == nil {
		t.Fatal("startTraceCmd() returned nil error without a BPF filter map")
	}
}

func TestTraceCommandSpecCopiesCLIInputs(t *testing.T) {
	opts := &cli.Options{
		CmdArgs:    []string{"/bin/true", "original"},
		EnvActions: []string{"TRACE=original", "REMOVE"},
	}
	spec := traceCommandSpecFromCLI(opts)
	opts.CmdArgs[1] = "mutated"
	opts.EnvActions[0] = "TRACE=mutated"

	if spec.args[1] != "original" || spec.envActions[0] != "TRACE=original" {
		t.Fatalf("trace command spec aliases CLI slices: %+v", spec)
	}
}

func TestStartTraceCmdRejectsEmptyCommandSpec(t *testing.T) {
	bootstrap := &traceTargetBootstrap{}
	_, _, _, err := bootstrap.startTraceCmd(traceCommandSpec{})
	if err == nil || err.Error() != "trace command is empty" {
		t.Fatalf("startTraceCmd() error = %v, want empty command error", err)
	}
}

func TestSetupOutputReturnsFileError(t *testing.T) {
	_, err := setupOutput(filepath.Join(t.TempDir(), "missing", "trace.log"), false)
	if err == nil {
		t.Fatal("setupOutput() returned nil error for an unavailable directory")
	}
}

func TestSetupOutputOwnsFileLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.log")
	output, err := setupOutput(path, false)
	if err != nil {
		t.Fatalf("setupOutput() error = %v", err)
	}
	if _, err := output.Write([]byte("getpid() = 1\n")); err != nil {
		t.Fatalf("TraceOutput.Write() error = %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("TraceOutput.Close() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if got := string(data); got != "getpid() = 1\n" {
		t.Fatalf("output file = %q, want trace line", got)
	}
}

func TestAttachToPidsReturnsFilterError(t *testing.T) {
	bootstrap := &traceTargetBootstrap{}
	_, _, err := bootstrap.attachToPids([]int{1})
	if err == nil {
		t.Fatal("attachToPids() returned nil error without a BPF filter map")
	}
}

func TestPendingTaskStorageUsesTaskLocalValue(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf() failed: %v", err)
	}

	if _, ok := spec.Maps["events_map"]; ok {
		t.Fatal("events_map should not remain as the syscall pending state map")
	}
	pending := spec.Maps["pending_task_storage"]
	if pending == nil {
		t.Fatal("pending_task_storage map missing from BPF object")
	}
	if pending.Type != ebpf.TaskStorage {
		t.Fatalf("pending task storage type = %s, want task storage", pending.Type)
	}
	if pending.KeySize != 4 {
		t.Fatalf("pending task storage key size = %d, want 4", pending.KeySize)
	}
	if pending.MaxEntries != 0 {
		t.Fatalf("pending task storage max entries = %d, want 0", pending.MaxEntries)
	}
	if pending.Flags&uint32(unix.BPF_F_NO_PREALLOC) == 0 {
		t.Fatal("pending task storage must use BPF_F_NO_PREALLOC")
	}
	if pending.ValueSize != 80 {
		t.Fatalf("pending task storage value size = %d, want 80 bytes", pending.ValueSize)
	}
}

func TestShouldQueueExitStatusSkipsExplicitAttachPid(t *testing.T) {
	session := newTestTraceSessionWithOptions(&cli.Options{AttachPids: []int{202}}, traceSessionDeps{
		HasCommand:    true,
		CommandWaiter: fakeTraceCommandWaiter{},
	})
	coordinator := session.exitStatusCoordinator()

	if coordinator.ShouldQueue(202) {
		t.Fatal("explicit attach pid exit status should not wait for command exit")
	}
	if !coordinator.ShouldQueue(303) {
		t.Fatal("non-attached command tracee exit status should wait for command exit")
	}
}

type fakeTraceCommandWaiter struct {
	result traceCommandExitResult
}

func (w fakeTraceCommandWaiter) Wait() traceCommandExitResult {
	if w.result.exited {
		return w.result
	}
	return traceCommandExitResult{exited: true}
}

func (fakeTraceCommandWaiter) Done() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
