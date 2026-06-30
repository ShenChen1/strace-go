package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

func makeWaitidSiginfo(signo uint32, code uint32, pid uint32, uid uint32, status uint32) []byte {
	data := make([]byte, waitidSiginfoSize)
	binary.LittleEndian.PutUint32(data[0:4], signo)
	binary.LittleEndian.PutUint32(data[8:12], code)
	binary.LittleEndian.PutUint32(data[16:20], pid)
	binary.LittleEndian.PutUint32(data[20:24], uid)
	binary.LittleEndian.PutUint32(data[24:28], status)
	binary.LittleEndian.PutUint64(data[32:40], 3)
	binary.LittleEndian.PutUint64(data[40:48], 4)
	return data
}

func makeWaitidRusage(userSec uint64, sysSec uint64) []byte {
	data := make([]byte, waitidRusageFull)
	binary.LittleEndian.PutUint64(data[0:8], userSec)
	binary.LittleEndian.PutUint64(data[16:24], sysSec)
	binary.LittleEndian.PutUint64(data[32:40], 99)
	return data
}

func newWaitidPolicyContext(reader *fetchPolicyMemoryReader, decoder *event.Decoder) *Context {
	return &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "waitid",
		Args:         [6]uint64{0, 0, 0x1000, 0, 0x2000},
		Ret:          0,
		ProbeRetExit: -1,
		Decoder:      decoder,
		Opts:         &cli.Options{},
		StrArgBuf:    make([]byte, waitidRusageOffset+waitidRusageFull),
	}
}

func TestWaitidSiginfoDoesNotReadWhenSnapshotMissing(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeWaitidSiginfo(17, 1, 42, 1000, 0)}
	decoder := event.NewDecoder()
	ctx := newWaitidPolicyContext(reader, decoder)

	got := decodeSiginfo(ctx, 0x1000)
	if got != "0x1000" {
		t.Fatalf("decodeSiginfo() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestWaitidSiginfoUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeWaitidSiginfo(0, 0, 0, 0, 0)}
	decoder := event.NewDecoder()
	ctx := newWaitidPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, waitidSiginfoOffset, makeWaitidSiginfo(17, 1, 42, 1000, 0))

	got := decodeSiginfo(ctx, 0x1000)
	if !strings.Contains(got, "si_signo=SIGCHLD") || !strings.Contains(got, "si_pid=42") {
		t.Fatalf("decodeSiginfo() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestWaitidSiginfoUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeWaitidSiginfo(0, 0, 0, 0, 0)}
	ctx := newWaitidPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: 0, Data: makeWaitidSiginfo(17, 1, 51, 1000, 0)},
	}

	got := decodeSiginfo(ctx, 0x1000)
	if !strings.Contains(got, "si_signo=SIGCHLD") || !strings.Contains(got, "si_pid=51") {
		t.Fatalf("decodeSiginfo() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestWaitidRusageUsesExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeWaitidRusage(1, 2)}
	decoder := event.NewDecoder()
	ctx := newWaitidPolicyContext(reader, decoder)
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, waitidRusageOffset, makeWaitidRusage(7, 8))

	got := decodeRusage(ctx, 0x2000)
	if !strings.Contains(got, "ru_utime={tv_sec=7") || !strings.Contains(got, "ru_stime={tv_sec=8") {
		t.Fatalf("decodeRusage() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestWaitidRusageUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeWaitidRusage(1, 2)}
	ctx := newWaitidPolicyContext(reader, event.NewDecoder())
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 4, ProbeRet: 0, Data: makeWaitidRusage(11, 12)},
	}

	got := decodeRusage(ctx, 0x2000)
	if !strings.Contains(got, "ru_utime={tv_sec=11") || !strings.Contains(got, "ru_stime={tv_sec=12") {
		t.Fatalf("decodeRusage() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestWaitidRusageVerboseUsesFullExitSnapshotWithoutMemoryRead(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeWaitidRusage(1, 2)}
	decoder := event.NewDecoder()
	ctx := newWaitidPolicyContext(reader, decoder)
	ctx.Opts.Verbose = true
	ctx.ProbeRetExit = 0
	putSmallSnapshot(ctx, waitidRusageOffset, makeWaitidRusage(7, 8))

	got := decodeRusage(ctx, 0x2000)
	if !strings.Contains(got, "ru_maxrss=99") {
		t.Fatalf("decodeRusage() = %q", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
