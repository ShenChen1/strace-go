package main

import (
	"bytes"
	"errors"
	"log"
	"testing"
)

type fakeBPFTargetPort struct {
	armCalls      int
	disarmCalls   int
	addCalls      []uint32
	deleted       []uint32
	armed         bool
	armErr        error
	disarmErr     error
	addErr        error
	deleteErr     error
	armedSnapshot uint32
}

func (p *fakeBPFTargetPort) armNextFork() error {
	p.armCalls++
	if p.armErr != nil {
		return p.armErr
	}
	p.armed = true
	return nil
}

func (p *fakeBPFTargetPort) disarmNextFork() error {
	p.disarmCalls++
	if p.disarmErr != nil {
		return p.disarmErr
	}
	p.armed = false
	return nil
}

func (p *fakeBPFTargetPort) addFilterPID(pid uint32) error {
	p.addCalls = append(p.addCalls, pid)
	return p.addErr
}

func (p *fakeBPFTargetPort) deleteFilterPID(pid uint32) error {
	p.deleted = append(p.deleted, pid)
	return p.deleteErr
}

func (p *fakeBPFTargetPort) armedForkPID() (uint32, bool) {
	if !p.armed {
		return 0, false
	}
	return p.armedSnapshot, true
}

func TestStartTraceCmdUsesTargetPortLifecycle(t *testing.T) {
	var logs bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousLogOutput)

	port := &fakeBPFTargetPort{armedSnapshot: 123}
	bootstrap := &traceTargetBootstrap{bpfRuntime: port}
	target, pid, _, err := bootstrap.startTraceCmd(traceCommandSpec{args: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("startTraceCmd() error = %v, want nil", err)
	}
	terminateTraceTarget(target)
	if pid <= 0 || len(port.addCalls) != 1 || port.addCalls[0] != uint32(pid) {
		t.Fatalf("target port calls = %+v, pid=%d, want one filter add", port, pid)
	}
	if port.armCalls != 1 || port.disarmCalls != 1 {
		t.Fatalf("arm/disarm calls = %d/%d, want 1/1", port.armCalls, port.disarmCalls)
	}
	if logs.Len() != 0 {
		t.Fatalf("default target startup log = %q, want empty", logs.String())
	}
}

func TestStartTraceCmdClearsTargetOnFilterFailure(t *testing.T) {
	port := &fakeBPFTargetPort{addErr: errors.New("filter update failed")}
	bootstrap := &traceTargetBootstrap{bpfRuntime: port}
	target, _, _, err := bootstrap.startTraceCmd(traceCommandSpec{args: []string{"/bin/true"}})
	if err == nil {
		t.Fatal("startTraceCmd() returned nil error after filter failure")
	}
	terminateTraceTarget(target)
	if port.armCalls != 1 || port.disarmCalls != 1 || len(port.deleted) != 1 {
		t.Fatalf("failure cleanup calls = %+v, want arm/disarm/delete", port)
	}
}

func TestTraceBPFRuntimeNilBoundariesAreExplicit(t *testing.T) {
	var runtime *traceBPFRuntime
	if err := runtime.Close(); err != nil {
		t.Fatalf("nil runtime Close() error = %v, want nil", err)
	}
	if _, err := runtime.newEventReader(); err == nil {
		t.Fatal("nil runtime newEventReader() returned nil error")
	}
	if err := runtime.configure(traceBPFConfig{}); err == nil {
		t.Fatal("nil runtime configure() returned nil error")
	}
	ports := runtime.readPorts()
	if ports.StackTraces != nil || ports.Stats != nil || ports.AttachExits != nil {
		t.Fatalf("nil runtime read ports = %+v, want empty", ports)
	}
}

func TestTraceBPFRuntimeCloseEmptyIsIdempotent(t *testing.T) {
	runtime := &traceBPFRuntime{}
	if err := runtime.Close(); err != nil {
		t.Fatalf("first Close() error = %v, want nil", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil", err)
	}
}
