package handler

import (
	"encoding/binary"
	"testing"
)

func TestDecodeFDStateObservation(t *testing.T) {
	data := make([]byte, FDStateSnapshotSize)
	binary.LittleEndian.PutUint32(data[0:4], uint32(int32(7)))
	binary.LittleEndian.PutUint32(data[4:8], FDStateFlagIdentity|FDStateFlagOffset|0x80)
	binary.LittleEndian.PutUint32(data[8:12], 0100644)
	binary.LittleEndian.PutUint64(data[16:24], 0x1020304050607080)
	binary.LittleEndian.PutUint64(data[24:32], 0x90a0b0c0d0e0f000)
	binary.LittleEndian.PutUint64(data[32:40], 0x1122334455667788)
	negativeOffset := int64(-9)
	binary.LittleEndian.PutUint64(data[40:48], uint64(negativeOffset))

	got, ok := DecodeFDStateObservation(data)
	if !ok {
		t.Fatal("DecodeFDStateObservation() failed for a complete snapshot")
	}
	want := FDStateObservation{
		FD:     7,
		Flags:  FDStateFlagIdentity | FDStateFlagOffset | 0x80,
		Mode:   0100644,
		Dev:    0x1020304050607080,
		Rdev:   0x90a0b0c0d0e0f000,
		Inode:  0x1122334455667788,
		Offset: -9,
	}
	if got != want {
		t.Fatalf("observation = %+v, want %+v", got, want)
	}
}

func TestDecodeFDStateObservationRejectsShortPayload(t *testing.T) {
	if _, ok := DecodeFDStateObservation(make([]byte, FDStateSnapshotSize-1)); ok {
		t.Fatal("DecodeFDStateObservation() accepted a short payload")
	}
}

func TestContextFDStateFindsTargetOrEventPID(t *testing.T) {
	ctx := &Context{
		Pid:       202,
		TargetPid: 101,
		FDStates: map[string]FDStateObservation{
			"202:7": {FD: 7, Inode: 42},
		},
	}

	got, ok := ctx.FDState(7)
	if !ok || got.Inode != 42 {
		t.Fatalf("FDState() = %+v, ok=%v; want event pid observation", got, ok)
	}
}
