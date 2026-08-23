package main

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestPossibleCPUCountMatchesRuntimeLibrary(t *testing.T) {
	want, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("ebpf.PossibleCPU() error = %v", err)
	}
	got, err := possibleCPUCount()
	if err != nil {
		t.Fatalf("possibleCPUCount() error = %v", err)
	}
	if got != uint32(want) {
		t.Fatalf("possibleCPUCount() = %d, want %d", got, want)
	}
}

func TestConfigureBPFRuntimeMetadataRequiresMapProvider(t *testing.T) {
	if err := configureBPFRuntimeMetadata(nil); err == nil {
		t.Fatal("configureBPFRuntimeMetadata(nil) returned nil error")
	}
}
