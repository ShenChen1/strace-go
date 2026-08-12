package main

import (
	"os"
	"testing"
)

func TestNewTraceTargetBootstrapRequiresBPFPort(t *testing.T) {
	if _, err := newTraceTargetBootstrap(nil); err == nil {
		t.Fatal("newTraceTargetBootstrap() accepted nil BPF port")
	}
}

func TestTraceTargetBootstrapResolveEmptyTargets(t *testing.T) {
	port := &fakeBPFTargetPort{}
	bootstrap := &traceTargetBootstrap{bpfRuntime: port}
	target, pid, seed, err := bootstrap.Resolve(traceTargetConfig{})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	if target != nil || pid != 0 || len(seed.paths) != 0 {
		t.Fatalf("Resolve() = target:%v pid:%d seed:%v, want empty result", target, pid, seed)
	}
	if len(port.addCalls) != 0 || port.armCalls != 0 {
		t.Fatalf("empty Resolve() touched target port: %+v", port)
	}
}

func TestTraceTargetBootstrapCloseReleasesInheritedFiles(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "inherited-fd-")
	if err != nil {
		t.Fatalf("create temp inherited file: %v", err)
	}
	bootstrap := &traceTargetBootstrap{inheritedFiles: []*os.File{file}}
	if err := bootstrap.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	if bootstrap.inheritedFiles != nil {
		t.Fatalf("inherited files after Close() = %v, want nil", bootstrap.inheritedFiles)
	}
	if _, err := file.Write([]byte("closed")); err == nil {
		t.Fatal("inherited file remained writable after bootstrap Close()")
	}
	if err := bootstrap.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil", err)
	}
}

func TestTraceTargetBootstrapNilResolveBoundary(t *testing.T) {
	var bootstrap *traceTargetBootstrap
	if _, _, _, err := bootstrap.Resolve(traceTargetConfig{}); err == nil {
		t.Fatal("nil bootstrap Resolve() returned nil error")
	}
}
