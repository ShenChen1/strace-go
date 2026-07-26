package main

// rawPayloadEvent is the narrow record view required by TLV payload projection.
type rawPayloadEvent struct {
	valid         bool
	args          [6]uint64
	eventType     uint16
	eventFlags    uint32
	ret           int64
	probeRetEnter int32
	probeRetExit  int32
	data          []byte
}
