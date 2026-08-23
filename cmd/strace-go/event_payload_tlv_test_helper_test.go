package main

import (
	"encoding/binary"
	"testing"
)

const (
	execPayloadSnapshotMagic      = 0x45584543
	execPayloadSnapshotHeaderSize = 32
	execPayloadArgSnapshotSize    = 56
	execPayloadArgSnapshotCount   = 48
	execPayloadEnvSnapshotCount   = 64
	execPayloadSnapshotSize       = execPayloadSnapshotHeaderSize +
		execPayloadArgSnapshotCount*execPayloadArgSnapshotSize +
		execPayloadEnvSnapshotCount*execPayloadArgSnapshotSize
)

type payloadTLVTestSection struct {
	kind     uint16
	arg      uint16
	flags    uint16
	userPtr  uint64
	userLen  uint32
	probeRet int32
	data     []byte
}

func payloadTLVBytes(t testing.TB, section payloadTLVTestSection) []byte {
	t.Helper()
	buf := make([]byte, payloadTLVHeaderSize+len(section.data))
	binary.LittleEndian.PutUint16(buf[0:2], section.kind)
	binary.LittleEndian.PutUint16(buf[2:4], section.arg)
	binary.LittleEndian.PutUint16(buf[4:6], section.flags)
	binary.LittleEndian.PutUint32(buf[8:12], section.userLen)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(section.data)))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(section.probeRet))
	binary.LittleEndian.PutUint64(buf[24:32], section.userPtr)
	copy(buf[payloadTLVHeaderSize:], section.data)
	return buf
}

func execJSONSnapshot() []byte {
	data := make([]byte, execPayloadSnapshotSize)
	binary.LittleEndian.PutUint32(data[0:4], execPayloadSnapshotMagic)
	binary.LittleEndian.PutUint16(data[4:6], 1)
	binary.LittleEndian.PutUint16(data[6:8], 1)
	return data
}
