package main

import (
	"os/exec"
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

func TestShouldQueueExitStatusSkipsExplicitAttachPid(t *testing.T) {
	session := &traceSession{
		cmd:  fakeStartedCommand(),
		opts: &cli.Options{AttachPids: []int{202}},
	}
	coordinator := session.exitStatusCoordinator()

	if coordinator.ShouldQueue(202) {
		t.Fatal("explicit attach pid exit status should not wait for command exit")
	}
	if !coordinator.ShouldQueue(303) {
		t.Fatal("non-attached command tracee exit status should wait for command exit")
	}
}

func fakeStartedCommand() *exec.Cmd {
	return &exec.Cmd{}
}
