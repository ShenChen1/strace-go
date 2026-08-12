package main

import (
	"os/exec"
	"testing"
)

func TestTraceTargetHandoffSnapshotsAndClosesFilterPIDs(t *testing.T) {
	port := &fakeBPFTargetPort{}
	targets := traceTargetConfig{attachPIDs: []int{202, 303, 202}}
	handoff, err := newTraceTargetHandoff(targets, nil, port, 101)
	if err != nil {
		t.Fatalf("newTraceTargetHandoff() error = %v", err)
	}
	targets.attachPIDs[0] = 404

	if err := handoff.Close(); err != nil {
		t.Fatalf("handoff.Close() error = %v", err)
	}
	if got, want := port.deleted, []uint32{101, 202, 303}; !sameUint32Slice(got, want) {
		t.Fatalf("deleted filter PIDs = %v, want %v", got, want)
	}
	if err := handoff.Close(); err != nil {
		t.Fatalf("second handoff.Close() error = %v", err)
	}
	if len(port.deleted) != 3 {
		t.Fatalf("second Close deleted filter PIDs again: %v", port.deleted)
	}
}

func TestTraceTargetHandoffTransferLeavesCleanupToRuntimeOwner(t *testing.T) {
	port := &fakeBPFTargetPort{}
	command := exec.Command("/bin/true")
	if err := command.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}
	targetRuntime := newTraceTargetRuntime(command)
	handoff, err := newTraceTargetHandoff(traceTargetConfig{}, targetRuntime, port, command.Process.Pid)
	if err != nil {
		t.Fatalf("newTraceTargetHandoff() error = %v", err)
	}
	if err := handoff.Transfer(); err != nil {
		t.Fatalf("handoff.Transfer() error = %v", err)
	}
	if err := handoff.Close(); err != nil {
		t.Fatalf("handoff.Close() after transfer error = %v", err)
	}
	if len(port.deleted) != 0 {
		t.Fatalf("transfer left filter cleanup behind: %v", port.deleted)
	}
	if err := targetRuntime.commandWaiter().Wait(); !err.exited {
		t.Fatalf("transferred command did not finish: %+v", err)
	}
}

func TestTraceTargetHandoffRejectsRepeatedTransfer(t *testing.T) {
	port := &fakeBPFTargetPort{}
	handoff, err := newTraceTargetHandoff(traceTargetConfig{}, nil, port, 0)
	if err != nil {
		t.Fatalf("newTraceTargetHandoff() error = %v", err)
	}
	if err := handoff.Transfer(); err != nil {
		t.Fatalf("first handoff.Transfer() error = %v", err)
	}
	if err := handoff.Transfer(); err == nil {
		t.Fatal("second handoff.Transfer() returned nil error")
	}
}

func TestTraceTargetHandoffRequiresBPFPort(t *testing.T) {
	if _, err := newTraceTargetHandoff(traceTargetConfig{}, nil, nil, 0); err == nil {
		t.Fatal("newTraceTargetHandoff() accepted nil BPF port")
	}
}

func sameUint32Slice(left, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
