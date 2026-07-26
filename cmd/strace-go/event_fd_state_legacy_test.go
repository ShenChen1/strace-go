package main

import (
	"encoding/binary"
	"os"
	"syscall"
	"testing"

	"strace-go/pkg/meta"
)

func TestUpdateFDMapIgnoresLegacyPipeExitSnapshot(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:          uint32(os.Getpid()),
		Tid:          uint32(os.Getpid()),
		Ret:          0,
		ProbeRetExit: 0,
		DataLen:      uint32(payloadExitArgOffset + 8),
	}
	binary.LittleEndian.PutUint32(eventRaw.StrArg[payloadExitArgOffset:], 21)
	binary.LittleEndian.PutUint32(eventRaw.StrArg[payloadExitArgOffset+4:], 22)

	fdMap := make(map[string]string)
	updateFDMapForTest(eventRaw, meta.Syscall{Name: "pipe"}, "", 101, fdMap)
	if len(fdMap) != 0 {
		t.Fatalf("fdMap entries = %d, want 0 without fd array payload section", len(fdMap))
	}
}

func TestUpdateFDMapIgnoresLegacySocketpairExitSnapshot(t *testing.T) {
	eventRaw := &bpfEvent{
		Pid:          uint32(os.Getpid()),
		Tid:          uint32(os.Getpid()),
		Args:         [6]uint64{syscall.AF_UNIX, syscall.SOCK_STREAM, 0, 0x2000},
		Ret:          0,
		ProbeRetExit: 0,
		DataLen:      uint32(payloadExitArgOffset + 8),
	}
	binary.LittleEndian.PutUint32(eventRaw.StrArg[payloadExitArgOffset:], 21)
	binary.LittleEndian.PutUint32(eventRaw.StrArg[payloadExitArgOffset+4:], 22)

	fdMap := make(map[string]string)
	updateFDMapForTest(eventRaw, meta.Syscall{Name: "socketpair"}, "", 101, fdMap)
	if len(fdMap) != 0 {
		t.Fatalf("fdMap entries = %d, want 0 without fd array payload section", len(fdMap))
	}
}

func TestUpdateFDMapIgnoresLegacyOpenatStringSnapshot(t *testing.T) {
	fdMap := make(map[string]string)
	eventRaw := &bpfEvent{
		Pid:           1234,
		Tid:           1234,
		Args:          [6]uint64{rawAtFdcwd, 0x1000},
		Ret:           7,
		ProbeRetEnter: 0,
		DataLen:       uint32(len("/tmp/legacy") + 1),
	}
	copy(eventRaw.StrArg[:], []byte("/tmp/legacy\x00"))

	updateFDMapForTest(eventRaw, meta.Syscall{Name: "openat"}, "0x1000", 101, fdMap)
	if len(fdMap) != 0 {
		t.Fatalf("fdMap entries = %d, want 0 without path payload section", len(fdMap))
	}
}

func TestUpdateFDMapIgnoresLegacyNetlinkSockaddrSnapshot(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		offset   int
		enterRet int32
		exitRet  int32
		dataLen  uint32
	}{
		{name: "bind", args: [6]uint64{7, 0x3000, 8}, offset: 0, enterRet: 0, exitRet: -1, dataLen: 8},
		{name: "getsockname", args: [6]uint64{7, 0x3000, 0x4000}, offset: payloadExitArgOffset, enterRet: -1, exitRet: 0, dataLen: uint32(payloadExitArgOffset + 8)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eventRaw := &bpfEvent{
				Pid:           1234,
				Tid:           1234,
				Args:          test.args,
				Ret:           0,
				ProbeRetEnter: test.enterRet,
				ProbeRetExit:  test.exitRet,
				DataLen:       test.dataLen,
			}
			binary.LittleEndian.PutUint16(eventRaw.StrArg[test.offset:], 16)
			binary.LittleEndian.PutUint32(eventRaw.StrArg[test.offset+4:], 42)

			fdMap := make(map[string]string)
			updateFDMapForTest(eventRaw, meta.Syscall{Name: test.name}, "", 101, fdMap)

			if len(fdMap) != 0 {
				t.Fatalf("fdMap entries = %d, want 0 without netlink sockaddr payload section", len(fdMap))
			}
		})
	}
}
