package handler

import (
	"encoding/binary"
	"fmt"
)

const (
	FDStateSnapshotSize = 48
	FDStateFlagIdentity = 1 << iota
	FDStateFlagOffset
	PayloadFDStateArgIndex = 0xffff
)

// FDStateObservation is an event-time snapshot of one returned file descriptor.
type FDStateObservation struct {
	FD     int32
	Flags  uint32
	Mode   uint32
	Dev    uint64
	Rdev   uint64
	Inode  uint64
	Offset int64
}

// DecodeFDStateObservation decodes the stable little-endian BPF payload layout.
func DecodeFDStateObservation(data []byte) (FDStateObservation, bool) {
	if len(data) < FDStateSnapshotSize {
		return FDStateObservation{}, false
	}
	return FDStateObservation{
		FD:     int32(binary.LittleEndian.Uint32(data[0:4])),
		Flags:  binary.LittleEndian.Uint32(data[4:8]),
		Mode:   binary.LittleEndian.Uint32(data[8:12]),
		Dev:    binary.LittleEndian.Uint64(data[16:24]),
		Rdev:   binary.LittleEndian.Uint64(data[24:32]),
		Inode:  binary.LittleEndian.Uint64(data[32:40]),
		Offset: int64(binary.LittleEndian.Uint64(data[40:48])),
	}, true
}

// FDState returns the event-time observation for a descriptor in this context.
func (ctx *Context) FDState(fd int32) (FDStateObservation, bool) {
	if ctx == nil || ctx.FDStates == nil {
		return FDStateObservation{}, false
	}
	for _, pid := range []int{ctx.TargetPid, ctx.Pid} {
		if observation, ok := ctx.FDStates[fmt.Sprintf("%d:%d", pid, fd)]; ok {
			return observation, true
		}
	}
	return FDStateObservation{}, false
}
