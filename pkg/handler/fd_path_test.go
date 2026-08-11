package handler

import (
	"encoding/binary"
	"testing"
)

func TestDecodeFDPathSnapshotWithState(t *testing.T) {
	data := make([]byte, FDPathStatePrefixSize+len("/dev/null")+1)
	binary.LittleEndian.PutUint32(data[0:4], 7)
	binary.LittleEndian.PutUint32(data[4:8], FDStateFlagIdentity|FDStateFlagOffset)
	binary.LittleEndian.PutUint32(data[8:12], 0020000)
	binary.LittleEndian.PutUint64(data[24:32], (1<<20)|3)
	copy(data[FDPathStatePrefixSize:], "/dev/null\x00")

	snapshot, ok := DecodeFDPathSnapshot(data)
	if !ok || snapshot.Path != "/dev/null" || !snapshot.HasObservation {
		t.Fatalf("snapshot = %+v, ok=%v; want path and state", snapshot, ok)
	}
	if snapshot.Observation.FD != 7 || snapshot.Observation.Rdev != (1<<20)|3 {
		t.Fatalf("observation = %+v, want fd 7 and kernel dev 1:3", snapshot.Observation)
	}
}

func TestDecodeFDPathSnapshotRejectsInvalidStatePrefix(t *testing.T) {
	data := make([]byte, FDPathStatePrefixSize+len("/dev/null"))
	binary.LittleEndian.PutUint32(data[0:4], 7)
	binary.LittleEndian.PutUint32(data[4:8], FDStateFlagIdentity|0x80)
	copy(data[FDPathStatePrefixSize:], "/dev/null")

	snapshot, ok := DecodeFDPathSnapshot(data)
	if !ok || snapshot.HasObservation {
		t.Fatalf("invalid-prefix snapshot = %+v, ok=%v; want path-only decode", snapshot, ok)
	}
	if snapshot.Path != string(data) {
		t.Fatalf("invalid-prefix path = %q, want preserved path-only bytes", snapshot.Path)
	}
	if _, ok := DecodeFDPathSnapshot(nil); ok {
		t.Fatal("DecodeFDPathSnapshot(nil) succeeded")
	}
}
