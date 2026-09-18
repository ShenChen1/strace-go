package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"strace-go/internal/architecture"
)

const (
	integrityEmitSignal = 128 + iota
	integrityCopyFailure
	integrityPendingFailure
	integrityPendingMismatch
	integrityOrphanExit
	integrityLifecycleFailure
	integrityPayloadTruncation
	integrityEmitEnter
	integrityEmitLifecycle
	integrityDropBeforeReserve
	integrityDropAfterWriteFailure
)

type integrityBPFHarness struct {
	collection *ebpf.Collection
	reader     *TraceEventReader
	integrity  *TraceIntegrity
}

func pinIntegrityTestCPU(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	var original unix.CPUSet
	if err := unix.SchedGetaffinity(0, &original); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	var chosen unix.CPUSet
	for cpu := 0; cpu < 1024; cpu++ {
		if original.IsSet(cpu) {
			chosen.Set(cpu)
			break
		}
	}
	if err := unix.SchedSetaffinity(0, &chosen); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.SchedSetaffinity(0, &original); err != nil {
			t.Error(err)
		}
		runtime.UnlockOSThread()
	})
}

func TestIntegrityBPFDeterministicEmissionFailures(t *testing.T) {
	for _, command := range []int{integrityDropBeforeReserve, integrityDropAfterWriteFailure} {
		t.Run(map[int]string{integrityDropBeforeReserve: "reserve", integrityDropAfterWriteFailure: "copy-discard"}[command], func(t *testing.T) {
			h := newIntegrityBPFHarness(t)
			pinIntegrityTestCPU(t)
			h.emit(t, integrityEmitEnter)
			h.emit(t, command)
			h.emit(t, integrityEmitLifecycle)
			h.drain(t)
			snapshot, stats := h.integrity.Snapshot(), h.stats(t)
			if snapshot.StreamGaps != 1 || snapshot.EstimatedLost != 1 || snapshot.LossEpoch != 1 {
				t.Fatalf("dropped attempt was not consumed exactly once: %+v", snapshot)
			}
			if stats.RingbufCopyFail+stats.RingbufReserveFail != 1 {
				t.Fatalf("failure accounting: %+v", stats)
			}
		})
	}
}

func newIntegrityBPFHarness(t *testing.T) integrityBPFHarness {
	t.Helper()
	if os.Getenv("STRACE_GO_TEST_INTEGRITY_BPF") != "1" {
		t.Skip("set STRACE_GO_TEST_INTEGRITY_BPF=1 for privileged producer failure tests")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	root := repoRootForTest(t)
	object := filepath.Join(t.TempDir(), "integrity.bpf.o")
	target, err := architecture.Parse(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	clangArch := "__TARGET_ARCH_x86"
	if target == architecture.ARM64 {
		clangArch = "__TARGET_ARCH_arm64"
	}
	command := exec.Command("clang", "-target", "bpfel", "-O2", "-g", "-mcpu=v3",
		"-D"+clangArch, "-I"+filepath.Join(root, "bpf"),
		"-c", filepath.Join(root, "test/fixtures/ebpf_integrity.bpf.c"), "-o", object)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile integrity fixture: %v\n%s", err, output)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	spec.Maps[bpfMapEvents].MaxEntries = uint32(os.Getpagesize())
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("load integrity fixture: %+v", verifier)
		}
		t.Fatalf("load integrity fixture: %+v", err)
	}
	t.Cleanup(collection.Close)
	reader, err := ringbuf.NewReader(collection.Maps[bpfMapEvents])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	integrity := newTraceIntegrity(traceIntegrityDeps{State: &TraceState{}, FDState: newFDStateStore(nil)})
	return integrityBPFHarness{collection: collection, integrity: integrity,
		reader: newTraceEventReader(TraceEventReaderDeps{
			Reader: reader, Decoder: newTraceRingbufRecordDecoder(), Integrity: integrity,
		})}
}

func (h integrityBPFHarness) emit(t *testing.T, command int) {
	t.Helper()
	if err := h.collection.Maps["test_command"].Put(uint32(0), uint32(command)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.collection.Programs["integrity_test"].Test(make([]byte, integrityEmitSignal)); err != nil {
		t.Fatalf("run producer command %d: %v", command, err)
	}
}

func (h integrityBPFHarness) drain(t *testing.T) {
	t.Helper()
	if err := h.reader.Drain(&ringbuf.Record{}); err != nil {
		t.Fatal(err)
	}
	if stats := h.reader.ReaderStats(); stats.RecordsInvalid != 0 {
		t.Fatalf("invalid producer records: %+v", stats)
	}
}

func (h integrityBPFHarness) stats(t *testing.T) bpfRuntimeStats {
	t.Helper()
	var values []bpfBpfStats
	if err := h.collection.Maps[bpfMapStats].Lookup(uint32(0), &values); err != nil {
		t.Fatal(err)
	}
	return sumBPFStatsValues(values)
}

func TestIntegrityBPFSharedSequenceAndSemanticFailures(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h := newIntegrityBPFHarness(t)
	for _, command := range []int{integrityEmitSignal, integrityEmitEnter, integrityEmitLifecycle, integrityPayloadTruncation} {
		h.emit(t, command)
	}
	h.drain(t)
	if h.integrity.Snapshot().Tainted || h.reader.ReaderStats().RecordsDecoded != 3 {
		t.Fatalf("healthy producer stream: %+v", h.reader.ReaderStats())
	}
	for _, command := range []int{integrityCopyFailure, integrityPendingFailure, integrityPendingMismatch, integrityOrphanExit, integrityLifecycleFailure} {
		h.emit(t, command)
	}
	h.emit(t, integrityEmitSignal)
	h.drain(t)
	snapshot := h.integrity.Snapshot()
	if !snapshot.Tainted || snapshot.LossEpoch != 4 || snapshot.FirstLossTimeNS == 0 {
		t.Fatalf("semantic failure propagation: %+v", snapshot)
	}
	stats := h.stats(t)
	if stats.IntegrityFirstTimeNS == 0 {
		t.Fatal("semantic failure missing from final stats")
	}
	if stats.OrphanExit != 1 {
		t.Fatalf("orphan diagnostic count = %d, want 1", stats.OrphanExit)
	}
}

func TestIntegrityBPFReserveFailureAndTailLoss(t *testing.T) {
	for _, tail := range []bool{false, true} {
		t.Run(map[bool]string{false: "followup", true: "tail"}[tail], func(t *testing.T) {
			h := newIntegrityBPFHarness(t)
			h.emit(t, integrityEmitSignal)
			h.drain(t)
			if h.integrity.Snapshot().Tainted {
				t.Fatal("initial healthy record was tainted")
			}
			for n := 0; n < os.Getpagesize(); n++ {
				h.emit(t, integrityEmitSignal)
			}
			h.drain(t)
			stats := h.stats(t)
			if stats.RingbufReserveFail == 0 || stats.RingbufCopyFail != 0 {
				t.Fatalf("ring pressure did not produce isolated reserve failure: %+v", stats)
			}
			if tail {
				h.integrity.Finalize(stats)
			} else {
				h.emit(t, integrityEmitSignal)
				h.drain(t)
			}
			if !h.integrity.Snapshot().Tainted {
				t.Fatal("producer loss did not taint the consumer")
			}
		})
	}
}
