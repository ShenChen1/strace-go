// Package procmem provides functions to read memory from a traced process
// via /proc/<pid>/mem with a ptrace fallback.
package procmem

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
)

// Reader holds state for reading a traced process's memory.
type Reader struct {
	TargetPid int
}

// NewReader creates a Reader bound to the given target PID (used as fallback).
func NewReader(targetPid int) *Reader {
	return &Reader{TargetPid: targetPid}
}

// Read reads size bytes from the address space of pid at addr.
// Falls back to the Reader's TargetPid and then ptrace if /proc/<pid>/mem fails.
func (r *Reader) Read(pid int, addr uint64, size int) ([]byte, error) {
	if size <= 0 { return nil, nil }
	out := make([]byte, size)
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(path)
	if err != nil { 
		path = fmt.Sprintf("/proc/%d/mem", r.TargetPid)
		f, err = os.Open(path)
		if err != nil { 
			buf := make([]byte, size)
			tmp := make([]byte, 8)
			for i := 0; i < size; i += 8 {
				n, _ := syscall.PtracePeekData(pid, uintptr(addr+uint64(i)), tmp)
				if n > 0 { copy(buf[i:], tmp) } else { break }
			}
			return buf, nil
		}
	}
	defer f.Close()
	n, _ := f.ReadAt(out, int64(addr))
	if n == 0 { return nil, fmt.Errorf("zero") }
	return out[:n], nil
}

// ReadRobust retries Read up to 50 times, optionally waiting for non-zero data.
// For sockaddr-like structures, it checks the first two bytes (address family) are non-zero.
func (r *Reader) ReadRobust(pid int, addr uint64, size int, waitOnZero bool) ([]byte, error) {
	for i := 0; i < 50; i++ {
		buf, err := r.Read(pid, addr, size)
		if err == nil {
			if !waitOnZero { return buf, nil }
			allZeros := true; for _, x := range buf { if x != 0 { allZeros = false; break } }
			if !allZeros { 
				if size >= 2 { fam := binary.LittleEndian.Uint16(buf[0:2]); if fam != 0 { return buf, nil } } else { return buf, nil }
			}
		}
		time.Sleep(1 * time.Millisecond)
	}
	return r.Read(pid, addr, size)
}
