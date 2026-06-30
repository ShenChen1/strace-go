package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func makeSysinfoSnapshot(uptime uint64) []byte {
	data := make([]byte, sysinfoStructSize)
	binary.LittleEndian.PutUint64(data[0:8], uptime)
	return data
}

func makeRlimitSnapshot(cur uint64, max uint64) []byte {
	data := make([]byte, rlimitStructSize)
	binary.LittleEndian.PutUint64(data[0:8], cur)
	binary.LittleEndian.PutUint64(data[8:16], max)
	return data
}

func makeUtsnameSnapshot(sysname string, nodename string) []byte {
	data := make([]byte, utsnameStructSize)
	copy(data[0:65], []byte(sysname))
	copy(data[65:130], []byte(nodename))
	return data
}

func newTypeMiscPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "sysinfo",
		Args:          [6]uint64{0x1000},
		Ret:           0,
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		ScMeta: meta.Syscall{
			Name:     "sysinfo",
			Args:     []string{"info"},
			ArgTypes: []string{"struct sysinfo *"},
		},
		StrArgBuf: make([]byte, BpfExitArgOffset+utsnameStructSize),
	}
}

func TestDecodeSysinfoDoesNotReadWhenSnapshotMissing(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSysinfoSnapshot(99)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)

	got, ok := decodeSysinfo(ctx, 0, "struct sysinfo *", 0x1000)
	if !ok || got != "0x1000" {
		t.Fatalf("decodeSysinfo() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeSysinfoUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeSysinfoSnapshot(99)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, makeSysinfoSnapshot(123))

	got, ok := decodeSysinfo(ctx, 0, "struct sysinfo *", 0x1000)
	if !ok || !strings.Contains(got, "uptime=123") {
		t.Fatalf("decodeSysinfo() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeSysinfoUsesPayloadStructSection(t *testing.T) {
	ctx := newTypeMiscPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: makeSysinfoSnapshot(321)},
	}

	got, ok := decodeSysinfo(ctx, 0, "struct sysinfo *", 0x1000)
	if !ok || !strings.Contains(got, "uptime=321") {
		t.Fatalf("decodeSysinfo() = %q, %v", got, ok)
	}
}

func TestDecodeRlimitUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeRlimitSnapshot(1, 2)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)
	ctx.ScMeta.Name = "setrlimit"
	ctx.ProbeRetEnter = 0
	putSmallSnapshot(ctx, BpfEnterArgOffset, makeRlimitSnapshot(7, 8))

	got, ok := decodeRlimitPointer(ctx, 1, "struct rlimit *", 0x1000)
	if !ok || got != "{rlim_cur=7, rlim_max=8}" {
		t.Fatalf("decodeRlimitPointer() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeRlimitUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeRlimitSnapshot(1, 2)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)
	ctx.ScMeta.Name = "getrlimit"
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, makeRlimitSnapshot(9, 10))

	got, ok := decodeRlimitPointer(ctx, 1, "struct rlimit *", 0x1000)
	if !ok || got != "{rlim_cur=9, rlim_max=10}" {
		t.Fatalf("decodeRlimitPointer() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeRlimitUsesPayloadStructSection(t *testing.T) {
	ctx := newTypeMiscPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.ScMeta.Name = "setrlimit"
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeRlimitSnapshot(13, 14)},
	}

	got, ok := decodeRlimitPointer(ctx, 1, "struct rlimit *", 0x1000)
	if !ok || got != "{rlim_cur=13, rlim_max=14}" {
		t.Fatalf("decodeRlimitPointer() = %q, %v", got, ok)
	}
}

func TestDecodePrlimitOldRlimitUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeRlimitSnapshot(1, 2)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)
	ctx.ScMeta.Name = "prlimit64"
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, makeRlimitSnapshot(11, 12))

	got, ok := decodeRlimitPointer(ctx, 3, "struct rlimit64 *", 0x2000)
	if !ok || got != "{rlim_cur=11, rlim_max=12}" {
		t.Fatalf("decodeRlimitPointer() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeUtsnameUsesPayloadStructSection(t *testing.T) {
	ctx := newTypeMiscPolicyContext(&fetchPolicyMemoryReader{}, event.NewDecoder())
	ctx.ScMeta.Name = "uname"
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: makeUtsnameSnapshot("Linux", "node-a")},
	}

	got, ok := decodeUtsname(ctx, 0, "struct utsname *", 0x1000)
	if !ok || !strings.Contains(got, `sysname="Linux"`) || !strings.Contains(got, `nodename="node-a"`) {
		t.Fatalf("decodeUtsname() = %q, %v", got, ok)
	}
}

func TestTypeMiscFlockUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFlockData(1, 2, 3, 4)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)
	ctx.Args[1] = 6 // F_SETLK
	ctx.ProbeRetEnter = 0
	putSmallSnapshot(ctx, BpfEnterArgOffset, makeFlockData(1, 2, 3, 4))

	got, ok := decodeFlock(ctx, 2, "struct flock *", 0x1000)
	if !ok || !strings.Contains(got, "l_type=F_WRLCK") {
		t.Fatalf("decodeFlock() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTypeMiscFlockUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFlockData(1, 2, 3, 4)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)
	ctx.Args[1] = 5 // F_GETLK
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, makeFlockData(2, 5, 6, 7))

	got, ok := decodeFlock(ctx, 2, "struct flock *", 0x1000)
	if !ok || !strings.Contains(got, "l_type=F_UNLCK") || !strings.Contains(got, "l_pid=7") {
		t.Fatalf("decodeFlock() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTypeMiscFOwnerExUsesEnterSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFOwnerExData(1, 42)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)
	ctx.Args[1] = 15 // F_SETOWN_EX
	ctx.ProbeRetEnter = 0
	putSmallSnapshot(ctx, BpfEnterArgOffset, makeFOwnerExData(1, 42))

	got, ok := decodeFOwnerEx(ctx, 2, "struct f_owner_ex *", 0x1000)
	if !ok || got != "{type=F_OWNER_PID, pid=42}" {
		t.Fatalf("decodeFOwnerEx() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTypeMiscFOwnerExUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeFOwnerExData(1, 42)}
	decoder := event.NewDecoder()
	ctx := newTypeMiscPolicyContext(reader, decoder)
	ctx.Args[1] = 16 // F_GETOWN_EX
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, BpfExitArgOffset, makeFOwnerExData(1, 43))

	got, ok := decodeFOwnerEx(ctx, 2, "struct f_owner_ex *", 0x1000)
	if !ok || got != "{type=F_OWNER_PID, pid=43}" {
		t.Fatalf("decodeFOwnerEx() = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
