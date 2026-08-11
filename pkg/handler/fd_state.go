package handler

import (
	"encoding/binary"
)

const (
	FDStateSnapshotSize             = 48
	FDStateFlagIdentity      uint32 = 1 << 0
	FDStateFlagOffset        uint32 = 1 << 1
	PayloadFDStateArgIndex          = 0xffff
	FDPathStatePrefixSize           = 48
	PayloadFDPathCwdArgIndex        = 0xfffe
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

// FDStateReader exposes immutable event-sourced FD state to formatters.
type FDStateReader interface {
	Path(pid int, fd int32) (string, bool)
	Cwd(pid int) (string, bool)
	Observation(pid int, fd int32) (FDStateObservation, bool)
}

// EventFDStateReader exposes the probe-site overlay for one event.
type EventFDStateReader interface {
	Path(fd int32) (string, bool)
	Cwd() (string, bool)
	Observation(fd int32) (FDStateObservation, bool)
}

// FDPathSnapshot combines an optional event-time FD observation with its
// bounded kernel path snapshot. The path-only form is valid when the state
// prefix could not be read but the probe-site dentry walk succeeded.
type FDPathSnapshot struct {
	Path           string
	Observation    FDStateObservation
	HasObservation bool
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
	if ctx == nil || ctx.FDStateView == nil {
		return FDStateObservation{}, false
	}
	for _, pid := range []int{ctx.TargetPid, ctx.Pid} {
		if observation, ok := ctx.FDStateView.Observation(pid, fd); ok {
			return observation, true
		}
	}
	return FDStateObservation{}, false
}
