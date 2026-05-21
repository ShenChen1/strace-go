// Package procmem provides functions to read memory from a traced process
// via process_vm_readv with fallbacks to /proc/<pid>/mem and ptrace.
package procmem

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// Reader holds state for reading memory.
type Reader struct {
	TargetPid int
	files     map[int]*os.File
}

// NewReader creates a new Reader.
func NewReader(targetPid int) *Reader {
	return &Reader{
		TargetPid: targetPid,
		files:     make(map[int]*os.File),
	}
}

// Close closes all open /proc/pid/mem files.
func (r *Reader) Close() {
	for _, f := range r.files {
		f.Close()
	}
}

// Read reads size bytes from the address space of pid at addr.
func (r *Reader) Read(pid int, addr uint64, size int) ([]byte, error) {
	if size <= 0 { return nil, nil }
	out := make([]byte, size)

	// Try process_vm_readv first
	n, err := r.readVM(pid, addr, out)
	if err == nil && n > 0 { return out[:n], nil }

	// Fallback to /proc/<pid>/mem
	f, ok := r.files[pid]
	if !ok && pid == r.TargetPid {
		path := fmt.Sprintf("/proc/%d/mem", pid)
		var err error
		f, err = os.Open(path)
		if err == nil {
			r.files[pid] = f
		}
	}

	if f != nil {
		n, _ := f.ReadAt(out, int64(addr))
		if n > 0 { return out[:n], nil }
	}

	// For other processes or if file read failed, try on-demand open (no cache)
	if pid != r.TargetPid {
		path := fmt.Sprintf("/proc/%d/mem", pid)
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
			n, _ := f.ReadAt(out, int64(addr))
			if n > 0 { return out[:n], nil }
		}
	}

	// Final fallback: PTRACE_PEEKDATA (requires attachment and stopped process)
	var data []byte
	buf := make([]byte, 8)
	for i := 0; i < size; i += 8 {
		n, err := syscall.PtracePeekData(pid, uintptr(addr+uint64(i)), buf)
		if err != nil || n == 0 {
			if i > 0 { return data, nil }
			return nil, err
		}
		data = append(data, buf[:n]...)
	}
	if len(data) > size { data = data[:size] }
	return data, nil
}

// readVM uses process_vm_readv syscall to read memory.
func (r *Reader) readVM(pid int, addr uint64, out []byte) (int, error) {
	type iovec struct {
		base unsafe.Pointer
		len  uintptr
	}

	localIov := iovec{
		base: unsafe.Pointer(&out[0]),
		len:  uintptr(len(out)),
	}

	remoteIov := iovec{
		base: unsafe.Pointer(uintptr(addr)),
		len:  uintptr(len(out)),
	}

	// Syscall number 310 for process_vm_readv on x86_64
	n, _, err := syscall.Syscall6(310, uintptr(pid), uintptr(unsafe.Pointer(&localIov)), 1, uintptr(unsafe.Pointer(&remoteIov)), 1, 0)
	if err != 0 { return 0, err }
	return int(n), nil
}

// ReadRobust retries Read up to 20 times, optionally waiting for non-zero data.
func (r *Reader) ReadRobust(pid int, addr uint64, size int, waitOnZero bool) ([]byte, error) {
	for i := 0; i < 20; i++ {
		buf, err := r.Read(pid, addr, size)
		if err == nil {
			if !waitOnZero { return buf, nil }
			allZeros := true; for _, x := range buf { if x != 0 { allZeros = false; break } }
			if !allZeros { return buf, nil }
		}
		time.Sleep(1 * time.Millisecond)
	}
	return r.Read(pid, addr, size)
}
