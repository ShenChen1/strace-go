package main

import "structs"

// bpfEvent is the legacy fixed-window sample shape kept only as an explicit
// projection fixture while product ringbuf decoding accepts event v2 records.
type bpfEvent struct {
	_             structs.HostLayout
	Pid           uint32
	SysId         uint32
	Tid           uint32
	EventVersion  uint16
	EventType     uint16
	EventFlags    uint32
	ProbeRetEnter int32
	ProbeRetExit  int32
	_             [4]byte
	EnterTime     uint64
	Duration      uint64
	Args          [6]uint64
	Ret           int64
	DataLen       uint32
	StackId       int32
	StrArg        [10400]uint8
}
