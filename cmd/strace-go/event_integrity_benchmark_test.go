package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func BenchmarkIntegrityConsumer(b *testing.B) {
	for _, mode := range []string{"baseline", "sequence-detection", "sequence-and-state", "tainted-recovery"} {
		b.Run(mode, func(b *testing.B) {
			state := &TraceState{}
			integrity := newTraceIntegrity(traceIntegrityDeps{State: state, FDState: newFDStateStore(nil)})
			if mode == "tainted-recovery" {
				integrity.InvalidRecord()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				ev := traceEventEnvelope{valid: true, seq: uint64(n + 1), pid: 10, tid: 11,
					enterTime: uint64(n / 2), eventType: bpfEventTypeEnter, eventFlags: bpfEventFlagGenericEnter}
				if n%2 != 0 {
					ev.eventType, ev.eventFlags = bpfEventTypeExit, 0
				}
				if mode != "baseline" {
					integrity.Observe(&ev)
				}
				if mode == "sequence-detection" {
					continue
				}
				update := state.handleEnvelope(ev)
				state.releaseTraceStateUpdate(update)
			}
		})
	}
}

func BenchmarkIntegrityBPFSequence(b *testing.B) {
	if os.Getenv("STRACE_GO_TEST_INTEGRITY_BPF") != "1" {
		b.Skip("set STRACE_GO_TEST_INTEGRITY_BPF=1 for kernel sequence benchmarks")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatal(err)
	}
	object := filepath.Join(b.TempDir(), "sequence.bpf.o")
	command := exec.Command("clang", "-target", "bpfel", "-O2", "-g", "-mcpu=v3",
		"-I../../bpf", "-c",
		"../../test/fixtures/ebpf_integrity_perf.bpf.c", "-o", object)
	if output, err := command.CombinedOutput(); err != nil {
		b.Fatalf("compile sequence benchmark: %v\n%s", err, output)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		b.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		b.Fatal(err)
	}
	defer collection.Close()
	for _, mode := range []string{"baseline", "per_cpu", "global_atomic"} {
		b.Run(mode, func(b *testing.B) {
			benchmarkIntegrityBPFProgram(b, collection.Programs[mode])
		})
	}
}

func benchmarkIntegrityBPFProgram(b *testing.B, program *ebpf.Program) {
	const batch = 4096
	var kernelNS atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		packet := make([]byte, 64)
		for pb.Next() {
			_, duration, err := program.Benchmark(packet, batch, nil)
			if err != nil {
				b.Error(err)
				return
			}
			kernelNS.Add(uint64(duration.Nanoseconds()))
		}
	})
	b.ReportMetric(float64(kernelNS.Load())/float64(b.N), "BPF-ns/attempt")
	b.ReportMetric(b.Elapsed().Seconds()*1e9/float64(b.N*batch), "wall-ns/attempt")
}
