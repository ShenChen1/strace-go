// Package event provides BPF event string decoding and path matching logic.
package event

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"strace-go/pkg/procmem"
)

// Decoder decodes string arguments from BPF events and matches trace paths.
type Decoder struct {
	MemReader *procmem.Reader
}

// NewDecoder creates a Decoder backed by the given memory reader.
func NewDecoder(memReader *procmem.Reader) *Decoder {
	return &Decoder{MemReader: memReader}
}

// DecodeString extracts a string from the target process's address space.
// It first tries the BPF-captured buffer, then falls back to reading /proc/<pid>/mem.
func (d *Decoder) DecodeString(pid int, ptr uint64, bpfData []byte, probeRet int32, scName string, expectedLen int) string {
	if ptr == 0 { return "" }
	if probeRet >= 0 {
		if scName == "read" || scName == "write" {
			limit := expectedLen; if limit > len(bpfData) { limit = len(bpfData) }
			if limit > 0 { return string(bpfData[:limit]) }
		} else if probeRet > 0 {
			limit := int(probeRet); if limit > len(bpfData) { limit = len(bpfData) }
			if limit > 0 && bpfData[limit-1] == 0 { limit-- }
			return string(bpfData[:limit])
		}
	}
	if data, err := d.MemReader.ReadRobust(pid, ptr, 512, false); err == nil {
		if idx := bytes.IndexByte(data, 0); idx != -1 { return string(data[:idx]) }; return string(data)
	}
	return ""
}

// MatchPath checks whether a syscall event matches any of the traced paths.
// Returns true if paths is empty (no filtering) or if the event's file argument
// or file descriptor resolves to one of the traced paths.
func MatchPath(pid int, fd int32, syscallName string, ptr uint64, argStr string, paths map[string]bool, fdMap map[string]string) bool {
	if len(paths) == 0 { return true }
	if ptr != 0 && argStr != "" {
		for p := range paths {
			if strings.Contains(argStr, p) { return true }
			if abs, err := filepath.Abs(p); err == nil && strings.Contains(argStr, abs) { return true }
		}
	}
	if fd >= 0 {
		link, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
		if link == "" { link = fdMap[fmt.Sprintf("%d:%d", pid, fd)] }
		for p := range paths {
			if strings.HasSuffix(link, p) || strings.Contains(link, p) { return true }
			if abs, err := filepath.Abs(p); err == nil && (strings.HasSuffix(link, abs) || strings.Contains(link, abs)) { return true }
		}
	}
	return false
}
