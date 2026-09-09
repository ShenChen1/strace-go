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

func TestDecodeTimespecIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
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

func TestDecodeTimespecUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Ret:     0,
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "clock_gettime"},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeTimeStruct(9, 10)},
		},
	}

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

func TestDecodeNanosleepRemainingUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Ret:     -4,
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "nanosleep"},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeTimeStruct(1, 2)},
		},
	}

	got, ok := decodeTimespec(ctx, 1, "struct timespec *", 0x1000)
	if !ok {
		t.Fatal("decodeTimespec returned ok=false")
	}
	if got != "{tv_sec=1, tv_nsec=2}" {
		t.Fatalf("decodeTimespec() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeTimevalIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		Ret:           0,
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
		Decoder:       decoder,
		ScMeta:        meta.Syscall{Name: "gettimeofday"},
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

func TestDecodeTimevalUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Ret:     0,
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "gettimeofday"},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: makeTimeStruct(3, 4)},
		},
	}

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

func TestRegistryDecodesKernelOldTimevalPayload(t *testing.T) {
	decoder := NewRegistry().StructDecoder("struct __kernel_old_timeval *")
	if decoder == nil {
		t.Fatal("kernel old timeval decoder is missing")
	}
	ctx := &Context{
		Ret:    0,
		ScMeta: meta.Syscall{Name: "gettimeofday"},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: makeTimeStruct(3, 4)},
		},
	}

	got, ok := decoder.Decode(ctx, 0, "struct __kernel_old_timeval *", 0x1000)
	if !ok {
		t.Fatal("kernel old timeval decoder returned ok=false")
	}
	if got != "{tv_sec=3, tv_usec=4}" {
		t.Fatalf("kernel old timeval = %q", got)
	}
}

func TestRegistryDecodesKernelOldItimervalPayload(t *testing.T) {
	decoder := NewRegistry().StructDecoder("struct __kernel_old_itimerval *")
	if decoder == nil {
		t.Fatal("kernel old itimerval decoder is missing")
	}
	ctx := &Context{
		Ret:    0,
		ScMeta: meta.Syscall{Name: "getitimer"},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeDoubleTimeStruct(5, 6, 7, 8)},
		},
	}

	got, ok := decoder.Decode(ctx, 1, "struct __kernel_old_itimerval *", 0x1000)
	if !ok {
		t.Fatal("kernel old itimerval decoder returned ok=false")
	}
	want := "{it_interval={tv_sec=5, tv_usec=6}, it_value={tv_sec=7, tv_usec=8}}"
	if got != want {
		t.Fatalf("kernel old itimerval = %q, want %q", got, want)
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

func TestDecodeItimervalIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeDoubleTimeStruct(9, 10, 11, 12)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
		ScMeta:       meta.Syscall{Name: "getitimer"},
	}

	got, ok := decodeItimerval(ctx, 1, "struct itimerval *", 0x1000)
	if !ok {
		t.Fatal("decodeItimerval returned ok=false")
	}
	if got != "0x1000" {
		t.Fatalf("decodeItimerval() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeItimervalUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeDoubleTimeStruct(9, 10, 11, 12)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Ret:     0,
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "getitimer"},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeDoubleTimeStruct(5, 6, 7, 8)},
		},
	}

	got, ok := decodeItimerval(ctx, 1, "struct itimerval *", 0x1000)
	if !ok {
		t.Fatal("decodeItimerval returned ok=false")
	}
	want := "{it_interval={tv_sec=5, tv_usec=6}, it_value={tv_sec=7, tv_usec=8}}"
	if got != want {
		t.Fatalf("decodeItimerval() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeTimezoneIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimezoneData(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
		ScMeta:       meta.Syscall{Name: "gettimeofday"},
	}

	got, ok := decodeTimezone(ctx, 1, "struct timezone *", 0x1000)
	if !ok {
		t.Fatal("decodeTimezone returned ok=false")
	}
	if got != "0x1000" {
		t.Fatalf("decodeTimezone() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeTimezoneUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimezoneData(9, 10)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Ret:     0,
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "gettimeofday"},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeTimezoneData(1, 2)},
		},
	}

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

func TestDecodeSettimeofdayTimezoneUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimezoneData(9, 10)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		Ret:     0,
		Decoder: event.NewDecoder(),
		ScMeta:  meta.Syscall{Name: "settimeofday"},
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeTimezoneData(1, 2)},
		},
	}

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
