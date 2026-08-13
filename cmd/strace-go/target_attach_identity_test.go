package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeTraceAttachIdentity struct {
	exitedValue bool
	exitedErr   error
	closeErr    error
	closeCalls  int
}

func (f *fakeTraceAttachIdentity) exited() (bool, error) {
	if f.exitedErr != nil {
		return false, f.exitedErr
	}
	return f.exitedValue, nil
}

func (f *fakeTraceAttachIdentity) close() error {
	f.closeCalls++
	return f.closeErr
}

type fakeTraceAttachIdentityOpener struct {
	identities map[int]*fakeTraceAttachIdentity
	openErrors map[int]error
	opened     []int
}

func (f *fakeTraceAttachIdentityOpener) open(pid int) (traceAttachIdentity, error) {
	f.opened = append(f.opened, pid)
	if err := f.openErrors[pid]; err != nil {
		return nil, err
	}
	identity := f.identities[pid]
	if identity == nil {
		return nil, errors.New("missing fake attach identity")
	}
	return identity, nil
}

func TestAttachToPidsUsesKernelIdentityHandshake(t *testing.T) {
	first := &fakeTraceAttachIdentity{}
	second := &fakeTraceAttachIdentity{}
	opener := &fakeTraceAttachIdentityOpener{
		identities: map[int]*fakeTraceAttachIdentity{101: first, 202: second},
		openErrors: map[int]error{},
	}
	port := &fakeBPFTargetPort{}
	bootstrap := &traceTargetBootstrap{
		bpfRuntime:     port,
		attachIdentity: opener,
	}

	pid, _, err := bootstrap.attachToPids([]int{101, 202})
	if err != nil {
		t.Fatalf("attachToPids() error = %v, want nil", err)
	}
	if pid != 101 {
		t.Fatalf("attachToPids() first pid = %d, want 101", pid)
	}
	if got := strings.TrimSpace(strings.Join(intsToStrings(opener.opened), ",")); got != "101,202" {
		t.Fatalf("opened pids = %q, want 101,202", got)
	}
	if len(port.addCalls) != 2 || port.addCalls[0] != 101 || port.addCalls[1] != 202 {
		t.Fatalf("filter add calls = %v, want [101 202]", port.addCalls)
	}
	if first.closeCalls != 1 || second.closeCalls != 1 {
		t.Fatalf("identity close calls = %d/%d, want 1/1", first.closeCalls, second.closeCalls)
	}
	if len(port.deleted) != 0 {
		t.Fatalf("filter delete calls = %v, want none", port.deleted)
	}
}

func TestAttachToPidsRollsBackWhenIdentityReportsExited(t *testing.T) {
	identity := &fakeTraceAttachIdentity{exitedValue: true}
	opener := &fakeTraceAttachIdentityOpener{
		identities: map[int]*fakeTraceAttachIdentity{303: identity},
		openErrors: map[int]error{},
	}
	port := &fakeBPFTargetPort{}
	bootstrap := &traceTargetBootstrap{bpfRuntime: port, attachIdentity: opener}

	_, _, err := bootstrap.attachToPids([]int{303})
	if err == nil || !strings.Contains(err.Error(), "exited before tracing started") {
		t.Fatalf("attachToPids() error = %v, want exited-target error", err)
	}
	if identity.closeCalls != 1 {
		t.Fatalf("identity close calls = %d, want 1", identity.closeCalls)
	}
	if len(port.deleted) != 1 || port.deleted[0] != 303 {
		t.Fatalf("filter delete calls = %v, want [303]", port.deleted)
	}
}

func TestAttachToPidsRollsBackOnIdentityErrors(t *testing.T) {
	tests := []struct {
		name        string
		exitedErr   error
		closeErr    error
		wantMessage string
	}{
		{name: "poll", exitedErr: errors.New("poll failed"), wantMessage: "check attach pid 404 state"},
		{name: "close", closeErr: errors.New("close failed"), wantMessage: "close attach pid 404 identity"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := &fakeTraceAttachIdentity{exitedErr: test.exitedErr, closeErr: test.closeErr}
			opener := &fakeTraceAttachIdentityOpener{
				identities: map[int]*fakeTraceAttachIdentity{404: identity},
				openErrors: map[int]error{},
			}
			port := &fakeBPFTargetPort{}
			bootstrap := &traceTargetBootstrap{bpfRuntime: port, attachIdentity: opener}

			_, _, err := bootstrap.attachToPids([]int{404})
			if err == nil || !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("attachToPids() error = %v, want %q", err, test.wantMessage)
			}
			if identity.closeCalls != 1 {
				t.Fatalf("identity close calls = %d, want 1", identity.closeCalls)
			}
			if len(port.deleted) != 1 || port.deleted[0] != 404 {
				t.Fatalf("filter delete calls = %v, want [404]", port.deleted)
			}
		})
	}
}

func TestAttachToPidsClosesIdentityWhenFilterUpdateFails(t *testing.T) {
	identity := &fakeTraceAttachIdentity{}
	opener := &fakeTraceAttachIdentityOpener{
		identities: map[int]*fakeTraceAttachIdentity{707: identity},
		openErrors: map[int]error{},
	}
	port := &fakeBPFTargetPort{addErr: errors.New("filter update failed")}
	bootstrap := &traceTargetBootstrap{bpfRuntime: port, attachIdentity: opener}

	_, _, err := bootstrap.attachToPids([]int{707})
	if err == nil || !strings.Contains(err.Error(), "add attach pid 707 to filter") {
		t.Fatalf("attachToPids() error = %v, want filter update error", err)
	}
	if identity.closeCalls != 1 {
		t.Fatalf("identity close calls = %d, want 1", identity.closeCalls)
	}
	if len(port.deleted) != 1 || port.deleted[0] != 707 {
		t.Fatalf("filter delete calls = %v, want [707]", port.deleted)
	}
}

func TestAttachToPidsRollsBackEarlierFiltersWhenIdentityOpenFails(t *testing.T) {
	first := &fakeTraceAttachIdentity{}
	opener := &fakeTraceAttachIdentityOpener{
		identities: map[int]*fakeTraceAttachIdentity{505: first},
		openErrors: map[int]error{606: errors.New("pidfd unavailable")},
	}
	port := &fakeBPFTargetPort{}
	bootstrap := &traceTargetBootstrap{bpfRuntime: port, attachIdentity: opener}

	_, _, err := bootstrap.attachToPids([]int{505, 606})
	if err == nil || !strings.Contains(err.Error(), "open attach pid 606 identity") {
		t.Fatalf("attachToPids() error = %v, want identity-open error", err)
	}
	if first.closeCalls != 1 {
		t.Fatalf("first identity close calls = %d, want 1", first.closeCalls)
	}
	if len(port.deleted) != 1 || port.deleted[0] != 505 {
		t.Fatalf("filter delete calls = %v, want [505]", port.deleted)
	}
}

func TestAttachBootstrapDoesNotUseKillPreflight(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/target_bootstrap.go"))
	if strings.Contains(source, "syscall.Kill(") {
		t.Fatal("target bootstrap still uses kill(pid, 0) instead of pidfd identity")
	}
}

func TestPidfdOpenerUsesExactTaskFlag(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/target_attach_identity.go"))
	if !strings.Contains(source, "unix.PidfdOpen(pid, pidfdThreadFlag)") {
		t.Fatal("pidfd opener does not bind the exact task for non-leader TID attach")
	}
}

func TestPidfdAttachIdentityRejectsInvalidPID(t *testing.T) {
	if _, err := (pidfdAttachIdentityOpener{}).open(0); err == nil {
		t.Fatal("pidfd opener accepted a non-positive pid")
	}
}

func TestPidfdAttachIdentityReportsKernelReadiness(t *testing.T) {
	readFile, writeFile, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	defer readFile.Close()
	defer writeFile.Close()
	duplicateFD, err := unix.Dup(int(readFile.Fd()))
	if err != nil {
		t.Fatalf("duplicate readiness fd: %v", err)
	}
	identity := &pidfdAttachIdentity{fd: duplicateFD}

	exited, err := identity.exited()
	if err != nil {
		t.Fatalf("exited() before readiness error = %v", err)
	}
	if exited {
		t.Fatal("exited() reported readiness before the fd became readable")
	}
	if _, err := writeFile.Write([]byte{1}); err != nil {
		t.Fatalf("write readiness byte: %v", err)
	}
	exited, err = identity.exited()
	if err != nil {
		t.Fatalf("exited() after readiness error = %v", err)
	}
	if !exited {
		t.Fatal("exited() = false after the fd became readable")
	}
	if err := identity.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(duplicateFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("closed pidfd probe F_GETFD error = %v, want EBADF", err)
	}
}

func intsToStrings(values []int) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strconv.Itoa(value)
	}
	return result
}
