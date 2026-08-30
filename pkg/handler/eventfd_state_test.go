package handler

import (
	"encoding/binary"
	"testing"
)

func TestDecodeEventFDState(t *testing.T) {
	data := make([]byte, EventFDStateSnapshotSize)
	binary.LittleEndian.PutUint64(data[0:8], 5)
	binary.LittleEndian.PutUint32(data[8:12], 17)
	binary.LittleEndian.PutUint32(data[12:16], 1)

	state, ok := DecodeEventFDState(data)
	if !ok || state.Count != 5 || state.ID != 17 || state.Semaphore != 1 {
		t.Fatalf("DecodeEventFDState() = %+v, %v", state, ok)
	}
}

func TestDecodeEventFDStateRejectsShortSnapshot(t *testing.T) {
	if _, ok := DecodeEventFDState(make([]byte, EventFDStateSnapshotSize-1)); ok {
		t.Fatal("DecodeEventFDState() accepted a short snapshot")
	}
}

func TestDecodeEventFDStateRejectsInvalidSemaphore(t *testing.T) {
	data := make([]byte, EventFDStateSnapshotSize)
	binary.LittleEndian.PutUint32(data[8:12], 17)
	binary.LittleEndian.PutUint32(data[12:16], 2)
	if _, ok := DecodeEventFDState(data); ok {
		t.Fatal("DecodeEventFDState() accepted an invalid semaphore value")
	}
}
