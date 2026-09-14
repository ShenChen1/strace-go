//go:build linux && (amd64 || arm64)

package architecture

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Native UAPI constants are resolved by the Go compiler for the build target.
const (
	StatSize        = int(unsafe.Sizeof(unix.Stat_t{}))
	StatNlinkOffset = int(unsafe.Offsetof(unix.Stat_t{}.Nlink))
	StatNlinkSize   = int(unsafe.Sizeof(unix.Stat_t{}.Nlink))
	StatModeOffset  = int(unsafe.Offsetof(unix.Stat_t{}.Mode))
	StatUIDOffset   = int(unsafe.Offsetof(unix.Stat_t{}.Uid))
	StatGIDOffset   = int(unsafe.Offsetof(unix.Stat_t{}.Gid))
	StatRdevOffset  = int(unsafe.Offsetof(unix.Stat_t{}.Rdev))
	StatBlksizeSize = int(unsafe.Sizeof(unix.Stat_t{}.Blksize))
	EpollEventSize  = int(unsafe.Sizeof(unix.EpollEvent{}))
	EpollDataOffset = int(unsafe.Offsetof(unix.EpollEvent{}.Fd))
)
