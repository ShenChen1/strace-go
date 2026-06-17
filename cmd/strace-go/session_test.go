package main

import (
	"bytes"
	"os/exec"
	"syscall"
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

func TestPtraceContinueSignal(t *testing.T) {
	tests := []struct {
		signal syscall.Signal
		want   int
	}{
		{signal: syscall.SIGTRAP, want: 0},
		{signal: syscall.SIGSTOP, want: 0},
		{signal: syscall.SIGUSR1, want: int(syscall.SIGUSR1)},
		{signal: syscall.SIGTERM, want: int(syscall.SIGTERM)},
	}

	for _, test := range tests {
		t.Run(test.signal.String(), func(t *testing.T) {
			if got := ptraceContinueSignal(test.signal); got != test.want {
				t.Fatalf("ptraceContinueSignal(%s) = %d, want %d", test.signal, got, test.want)
			}
		})
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
		t.Fatal("explicit attach pid exit status should not wait for ptrace wait4")
	}
	if !session.shouldQueueExitStatus(303) {
		t.Fatal("non-attached command tracee exit status should wait for ptrace wait4")
	}
}

func fakeStartedCommand() *exec.Cmd {
	return &exec.Cmd{}
}
