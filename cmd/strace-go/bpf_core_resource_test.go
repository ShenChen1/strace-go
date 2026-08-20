package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeBPFCoreResource struct {
	closed     bool
	closeCalls int
}

func (r *fakeBPFCoreResource) coreMap(string) *ebpf.Map {
	return nil
}

func (r *fakeBPFCoreResource) program(string) *ebpf.Program {
	return nil
}

func (r *fakeBPFCoreResource) Close() error {
	r.closed = true
	r.closeCalls++
	return nil
}

var _ io.Closer = (*fakeBPFCoreResource)(nil)
var _ bpfCoreResourceProvider = (*fakeBPFCoreResource)(nil)

func TestGeneratedBPFObjectsImplementCoreResourceProvider(t *testing.T) {
	var provider bpfCoreResourceProvider = &bpfObjects{}
	if provider.coreMap(bpfMapEvents) != nil {
		t.Fatal("empty generated BPF objects unexpectedly expose an events map")
	}
	if provider.program("trace_sys_enter") != nil {
		t.Fatal("empty generated BPF objects unexpectedly expose a core program")
	}
}

func TestBPFObjectBundleClosesCoreCapabilityOnce(t *testing.T) {
	core := &fakeBPFCoreResource{}
	bundle := &bpfObjectBundle{core: core}
	if err := bundle.Close(); err != nil {
		t.Fatalf("first bundle Close() error = %v", err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatalf("second bundle Close() error = %v", err)
	}
	if !core.closed || core.closeCalls != 1 {
		t.Fatalf("core close state = closed:%v calls:%d, want closed:true calls:1", core.closed, core.closeCalls)
	}
}

func TestCoreResourceConsumersUseCapabilityBoundary(t *testing.T) {
	root := repoRootForTest(t)
	files := []string{
		"cmd/strace-go/bpf_runtime.go",
		"cmd/strace-go/bpf_setup.go",
		"cmd/strace-go/bpf_attach.go",
		"cmd/strace-go/bpf_config.go",
		"cmd/strace-go/syscall_filter.go",
		"cmd/strace-go/bpf_routes.go",
		"cmd/strace-go/bpf_read_ports.go",
	}
	for _, name := range files {
		source := readTextFile(t, filepath.Join(root, name))
		if strings.Contains(source, "*bpfObjects") {
			t.Fatalf("%s still exposes generated BPF object type", name)
		}
		if strings.Contains(source, "bpfCoreMap(") {
			t.Fatalf("%s bypasses the typed core map provider", name)
		}
	}
	loaderSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_object_loader.go"))
	if !strings.Contains(loaderSource, "type bpfCoreResourceProvider interface") {
		t.Fatal("core resource boundary interface is missing")
	}
	if !strings.Contains(loaderSource, "bpfCoreResourceProvider") {
		t.Fatal("core resource bundle does not use the capability interface")
	}
}
