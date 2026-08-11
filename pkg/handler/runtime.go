package handler

import "time"

// RuntimeServices contains the session-scoped enrichment state used while
// formatting syscall events. A trace session owns one implementation and
// calls it from its single event-consumer goroutine.
type RuntimeServices interface {
	SocketInfo(proto string, inode string) string
	NextFiemapCall(pid int) int
}

// PathStat is the metadata needed for -yy rendering without exposing an OS
// specific syscall.Stat_t to handlers.
type PathStat struct {
	Mode  uint64
	Inode uint64
	Rdev  uint64
}

// FDMetadataServices isolates procfs and filesystem metadata reads from event
// decoding and FD state transitions.
type FDMetadataServices interface {
	EventfdInfo(pid int, fd int32, initialCount uint64, flags uint64, forceCount bool) string
	FDPath(pid int, fd int32) (string, bool)
	FDStat(pid int, fd int32) (PathStat, bool)
	CWDPath(pid int) (string, bool)
	FDOffset(pid int, fd int32) (int64, bool)
	PathStat(path string) (PathStat, bool)
}

// Runtime keeps formatter state local to one trace session. Keeping this state
// out of package globals prevents parallel sessions from sharing observations.
type Runtime struct {
	netCache      map[string]string
	netCacheValid time.Time
	lastEventfdID int
	fiemapCalls   map[int]int
}

// NewRuntime creates an empty session-scoped runtime.
func NewRuntime() *Runtime {
	return &Runtime{
		lastEventfdID: -1,
		fiemapCalls:   make(map[int]int),
	}
}

// NextFiemapCall returns the one-based invocation number for a process within
// this runtime. It preserves fiemap's bounded synthetic fallback per session.
func (r *Runtime) NextFiemapCall(pid int) int {
	if r == nil {
		return 1
	}
	if r.fiemapCalls == nil {
		r.fiemapCalls = make(map[int]int)
	}
	r.fiemapCalls[pid]++
	return r.fiemapCalls[pid]
}
