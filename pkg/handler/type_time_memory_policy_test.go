package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func makeTimeStruct(sec int64, subsec uint64) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(data[8:16], subsec)
	return data
}

func putTypeTimeSnapshot(ctx *Context, offset int, data []byte) {
	copy(ctx.StrArgBuf[offset:], data)
	end := uint32(offset + len(data))
	if ctx.DataLen < end {
		ctx.DataLen = end
	}
}

func makeDoubleTimeStruct(aSec int64, aSub uint64, bSec int64, bSub uint64) []byte {
	data := make([]byte, 32)
	copy(data[0:16], makeTimeStruct(aSec, aSub))
	copy(data[16:32], makeTimeStruct(bSec, bSub))
	return data
}

func makeTimezoneData(west int32, dst int32) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], uint32(west))
	binary.LittleEndian.PutUint32(data[4:8], uint32(dst))
	return data
}

func TestDecodeTimespecDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Ret:           0,
		ProbeRetEnter: -1,
		Decoder:       decoder,
		ScMeta:        meta.Syscall{Name: "clock_gettime"},
		StrArgBuf:     make([]byte, BpfExitArgOffset+16),
	}

	got, ok := decodeTimespec(ctx, 1, "struct timespec *", 0x1000)
	if !ok {
		t.Fatal("decodeTimespec returned ok=false")
	}
	if got != "0x1000" {
		t.Fatalf("decodeTimespec() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeTimespecUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Ret:           0,
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
		Decoder:       decoder,
		ScMeta:        meta.Syscall{Name: "clock_gettime"},
		StrArgBuf:     make([]byte, BpfExitArgOffset+16),
	}
	putTypeTimeSnapshot(ctx, BpfExitArgOffset, makeTimeStruct(9, 10))

	got, ok := decodeTimespec(ctx, 1, "struct timespec *", 0x1000)
	if !ok {
		t.Fatal("decodeTimespec returned ok=false")
	}
	if got != "{tv_sec=9, tv_nsec=10}" {
		t.Fatalf("decodeTimespec() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeTimevalUsesExitSnapshotWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	decoder := event.NewDecoder()
	buf := make([]byte, BpfExitArgOffset+16)
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Ret:           0,
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
		Decoder:       decoder,
		ScMeta:        meta.Syscall{Name: "gettimeofday"},
		StrArgBuf:     buf,
	}
	putTypeTimeSnapshot(ctx, BpfExitArgOffset, makeTimeStruct(3, 4))

	got, ok := decodeTimeval(ctx, 0, "struct timeval *", 0x1000)
	if !ok {
		t.Fatal("decodeTimeval returned ok=false")
	}
	if got != "{tv_sec=3, tv_usec=4}" {
		t.Fatalf("decodeTimeval() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeTimevalFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Ret:           0,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		ScMeta:        meta.Syscall{Name: "gettimeofday"},
		StrArgBuf:     make([]byte, BpfExitArgOffset+16),
	}

	got, ok := decodeTimeval(ctx, 0, "struct timeval *", 0x1000)
	if !ok {
		t.Fatal("decodeTimeval returned ok=false")
	}
	if got != "0x1000" {
		t.Fatalf("decodeTimeval() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeItimervalUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeDoubleTimeStruct(9, 10, 11, 12)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
		ScMeta:       meta.Syscall{Name: "getitimer"},
		StrArgBuf:    make([]byte, BpfExitArgOffset+32),
	}
	putTypeTimeSnapshot(ctx, BpfExitArgOffset, makeDoubleTimeStruct(1, 2, 3, 4))

	got, ok := decodeItimerval(ctx, 1, "struct itimerval *", 0x1000)
	if !ok {
		t.Fatal("decodeItimerval returned ok=false")
	}
	want := "{it_interval={tv_sec=1, tv_usec=2}, it_value={tv_sec=3, tv_usec=4}}"
	if got != want {
		t.Fatalf("decodeItimerval() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeTimezoneUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimezoneData(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
		ScMeta:       meta.Syscall{Name: "gettimeofday"},
		StrArgBuf:    make([]byte, BpfExitArgOffset+24),
	}
	putTypeTimeSnapshot(ctx, BpfExitArgOffset+16, makeTimezoneData(1, 2))

	got, ok := decodeTimezone(ctx, 1, "struct timezone *", 0x1000)
	if !ok {
		t.Fatal("decodeTimezone returned ok=false")
	}
	if got != "{tz_minuteswest=1, tz_dsttime=2}" {
		t.Fatalf("decodeTimezone() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeItimerspecFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeDoubleTimeStruct(9, 10, 11, 12)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Ret:           0,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		ScMeta:        meta.Syscall{Name: "timerfd_gettime"},
		StrArgBuf:     make([]byte, BpfExitArgOffset+32),
	}

	got, ok := decodeItimerspec(ctx, 1, "struct itimerspec *", 0x1000)
	if !ok {
		t.Fatal("decodeItimerspec returned ok=false")
	}
	if got != "0x1000" {
		t.Fatalf("decodeItimerspec() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
