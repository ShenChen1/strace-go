package handler

import "encoding/binary"

const (
	EventFDStateSnapshotSize    = 16
	PayloadEventFDStateArgIndex = 0xfffc
)

// EventFDState is an event-time snapshot of one eventfd object.
type EventFDState struct {
	Count     uint64
	ID        int32
	Semaphore uint32
}

// DecodeEventFDState decodes the stable little-endian BPF payload layout.
func DecodeEventFDState(data []byte) (EventFDState, bool) {
	if len(data) < EventFDStateSnapshotSize {
		return EventFDState{}, false
	}
	state := EventFDState{
		Count:     binary.LittleEndian.Uint64(data[0:8]),
		ID:        int32(binary.LittleEndian.Uint32(data[8:12])),
		Semaphore: binary.LittleEndian.Uint32(data[12:16]),
	}
	if state.ID < 0 || state.Semaphore > 1 {
		return EventFDState{}, false
	}
	return state, true
}
