package main

import (
	"encoding/binary"
	"io"
	"testing"

	"strace-go/pkg/meta"
)

func TestTraceStatePendingFreelistReusesAfterRelease(t *testing.T) {
	sysID := benchmarkSyscallID("getpid")
	enterRaw := benchmarkTraceEventV2Sample(bpfEventTypeEnter, sysID, 1000, 0, 0)
	exitRaw := benchmarkTraceEventV2Sample(bpfEventTypeExit, sysID, 1050, 50, 0)
	enter, ok := decodeTraceEventV2Envelope(enterRaw)
	if !ok {
		t.Fatal("benchmark enter sample was rejected")
	}
	exit, ok := decodeTraceEventV2Envelope(exitRaw)
	if !ok {
		t.Fatal("benchmark exit sample was rejected")
	}
	state := newTraceStateWithDeferredExit(false)
	state.handleEnvelope(enter)
	update := state.handleEnvelope(exit)
	if update.pendingEnter == nil {
		t.Fatal("warm-up pair did not produce a pending enter")
	}
	state.releaseTraceStateUpdate(update)

	allocs := testing.AllocsPerRun(100, func() {
		state.handleEnvelope(enter)
		update := state.handleEnvelope(exit)
		state.releaseTraceStateUpdate(update)
	})
	if allocs != 0 {
		t.Fatalf("steady-state pending pair allocations = %.1f, want zero", allocs)
	}
}

func BenchmarkTraceEventDecodeState(b *testing.B) {
	sysID := benchmarkSyscallID("getpid")
	enterRaw := benchmarkTraceEventV2Sample(bpfEventTypeEnter, sysID, 1000, 0, 0)
	exitRaw := benchmarkTraceEventV2Sample(bpfEventTypeExit, sysID, 1050, 50, 0)
	state := newTraceStateWithDeferredExit(false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter, ok := decodeTraceEventV2Envelope(enterRaw)
		if !ok {
			b.Fatal("benchmark enter sample was rejected")
		}
		state.handleEnvelope(enter)

		exit, ok := decodeTraceEventV2Envelope(exitRaw)
		if !ok {
			b.Fatal("benchmark exit sample was rejected")
		}
		update := state.handleEnvelope(exit)
		state.releaseTraceStateUpdate(update)
	}
}

func TestJSONEventWriterReusesSyscallEventStorage(t *testing.T) {
	if raceBuild {
		t.Skip("allocation counts include race instrumentation")
	}
	sysID := benchmarkSyscallID("getpid")
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})
	event := syscallEventContext{
		view: syscallEventView{
			valid:        true,
			eventVersion: traceEventV2Version,
			pid:          101,
			tid:          101,
			sysID:        sysID,
			eventType:    bpfEventTypeExit,
			ret:          0,
			duration:     50,
			enterTime:    950,
		},
		meta: meta.Syscall{Name: "getpid"},
	}

	writer.WriteRaw(event)
	allocs := testing.AllocsPerRun(100, func() {
		writer.WriteRaw(event)
	})
	if allocs != 0 {
		t.Fatalf("steady-state JSON syscall writer allocations = %.1f, want zero", allocs)
	}
}

func BenchmarkJSONEventWriter(b *testing.B) {
	sysID := benchmarkSyscallID("getpid")
	writer := newJSONEventWriter(JSONEventWriterDeps{Out: io.Discard})
	event := syscallEventContext{
		view: syscallEventView{
			valid:        true,
			eventVersion: traceEventV2Version,
			pid:          101,
			tid:          101,
			sysID:        sysID,
			eventType:    bpfEventTypeExit,
			ret:          0,
			duration:     50,
			enterTime:    950,
		},
		meta: meta.Syscall{Name: "getpid"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.WriteRaw(event)
	}
}

func benchmarkSyscallID(name string) uint32 {
	for id, syscall := range meta.SyscallTable {
		if syscall.Name == name {
			return id
		}
	}
	panic("benchmark syscall is missing: " + name)
}

func benchmarkTraceEventV2Sample(
	eventType uint16,
	sysID uint32,
	tsNs uint64,
	duration uint64,
	ret int64,
) []byte {
	bodyLen := traceEventV2EnterBodyLen
	if eventType == bpfEventTypeExit {
		bodyLen = traceEventV2ExitBodyLen
	}
	raw := make([]byte, traceEventV2HeaderLen+bodyLen)
	binary.LittleEndian.PutUint16(raw[0:2], traceEventV2Version)
	binary.LittleEndian.PutUint16(raw[2:4], eventType)
	flags := uint16(0)
	if eventType == bpfEventTypeEnter {
		flags = uint16(bpfEventFlagGenericEnter)
	}
	binary.LittleEndian.PutUint16(raw[4:6], flags)
	binary.LittleEndian.PutUint16(raw[6:8], traceEventV2HeaderLen)
	binary.LittleEndian.PutUint32(raw[8:12], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[12:16], 101)
	binary.LittleEndian.PutUint32(raw[16:20], 101)
	binary.LittleEndian.PutUint32(raw[20:24], sysID)
	binary.LittleEndian.PutUint64(raw[32:40], tsNs)

	bodyOffset := traceEventV2HeaderLen
	binary.LittleEndian.PutUint64(raw[bodyOffset:bodyOffset+8], uint64(ret))
	if eventType == bpfEventTypeEnter {
		binary.LittleEndian.PutUint32(raw[bodyOffset+64:bodyOffset+68], 0)
		return raw
	}
	binary.LittleEndian.PutUint64(raw[bodyOffset+8:bodyOffset+16], duration)
	binary.LittleEndian.PutUint32(raw[bodyOffset+64:bodyOffset+68], 0)
	binary.LittleEndian.PutUint32(raw[bodyOffset+72:bodyOffset+76], 0)
	return raw
}
