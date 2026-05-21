package event

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/procmem"
)

type Decoder struct {
	MemReader *procmem.Reader
}

func NewDecoder(mr *procmem.Reader) *Decoder {
	return &Decoder{MemReader: mr}
}

// DecodeString decodes a string from BPF-captured data or process memory.
func (d *Decoder) DecodeString(pid int, ptr uint64, bpfData []byte, probeRet int32, scName string, limit int) string {
	if ptr == 0 { return "NULL" }

	var raw []byte
	found := false

	// Try BPF data first
	if len(bpfData) > 0 {
		if idx := bytes.IndexByte(bpfData, 0); idx != -1 {
			if idx > 0 || probeRet >= 0 {
				raw = bpfData[:idx]
				found = true
			}
		}
	}

	if !found {
		// Fallback to process memory
		if data, err := d.MemReader.ReadRobust(pid, ptr, 512, false); err == nil {
			if idx := bytes.IndexByte(data, 0); idx != -1 {
				raw = data[:idx]
			} else {
				raw = data
			}
			found = true
		}
	}

	if found {
		return format.Buffer(raw, limit, 0)
	}

	return fmt.Sprintf("%#x", ptr)
}

// DecodeStringRaw decodes a string without quoting it.
func (d *Decoder) DecodeStringRaw(pid int, ptr uint64, bpfData []byte, probeRet int32) string {
	if ptr == 0 { return "NULL" }
	if len(bpfData) > 0 {
		if idx := bytes.IndexByte(bpfData, 0); idx != -1 {
			if idx > 0 || probeRet >= 0 { return string(bpfData[:idx]) }
		}
	}
	if data, err := d.MemReader.ReadRobust(pid, ptr, 512, false); err == nil {
		if idx := bytes.IndexByte(data, 0); idx != -1 { return string(data[:idx]) }
		return string(data)
	}
	return fmt.Sprintf("%#x", ptr)
}

// MatchPath checks if the syscall matches any of the paths in the filter list.
func MatchPath(pid int, fd int32, scName string, ptr uint64, rawStrArg string, tracePaths map[string]bool, fdMap map[string]string) bool {
	if len(tracePaths) == 0 { return true }
	
	p := rawStrArg
	if (p == "" || p == "NULL" || strings.HasPrefix(p, "0x")) && fd != -1 {
		if path, ok := fdMap[fmt.Sprintf("%d:%d", pid, fd)]; ok { 
			p = path 
		}
	}
	
	// Strip quotes if present
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		p = p[1 : len(p)-1]
	}

	if p == "" || p == "NULL" || strings.HasPrefix(p, "0x") { return false }
	
	for tp := range tracePaths {
		if p == tp || strings.HasPrefix(p, tp+"/") { return true }
		
		absP := p
		if !strings.HasPrefix(p, "/") {
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
				absP = cwd + "/" + p
			}
		}
		
		absTP := tp
		if !strings.HasPrefix(tp, "/") {
			if cwd, err := os.Getwd(); err == nil {
				absTP = cwd + "/" + tp
			}
		}

		if absP == absTP || strings.HasPrefix(absP, absTP+"/") { return true }
	}
	return false
}
