package event

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/procmem"
)

// IMPACT: Added StringLimit field to Decoder to allow DecodeString to apply command-line formatting limits independently from internal buffer size limits.
type Decoder struct {
	MemReader     procmem.MemoryReader
	HexEscapeMode int
	StringLimit   int
}

func NewDecoder(mr procmem.MemoryReader) *Decoder {
	return &Decoder{MemReader: mr, HexEscapeMode: 0}
}

// IMPACT: Refined DecodeString to allow fallback memory reading even when probeRet is -2 (EFAULT),
// ensuring partially valid strings (like those truncated at page boundaries) are correctly decoded.
// parseBPFData extracts string raw data from BPF buffer.
func parseBPFData(bpfData []byte, probeRet int32) (bpfRaw []byte, bpfFound bool, raw []byte, found bool) {
	if len(bpfData) == 0 {
		return nil, false, nil, false
	}
	idx := bytes.IndexByte(bpfData, 0)
	if idx != -1 {
		bpfRaw = bpfData[:idx]
		bpfFound = true
		// If null terminator is at the very last byte, it is likely BPF buffer boundary forced null.
		// We do not treat it as a naturally terminating string so it falls back to MemReader if needed.
		bound := len(bpfData)
		if probeRet > 0 && int(probeRet) < bound {
			bound = int(probeRet)
		}
		if probeRet >= 0 && idx <= bound-1 {
			raw = bpfRaw
			found = true
		}
	} else {
		maxLen := len(bpfData)
		if maxLen > 4096 {
			maxLen = 4096
		}
		bpfRaw = bpfData[:maxLen]
		bpfFound = true
	}
	return
}

// IMPACT: Robustly decodes strings. Uses BPF data when zero-terminator is found or limit reached. Otherwise falls back to process memory reading, handling ESRCH or page-boundary EFAULT.
// IMPACT: Restrict DecodeString direct return and fallback decisions to probeRet >= 0 to prevent EFAULT and unprobed cases from reading dirty per-CPU buffer cache.
func (d *Decoder) DecodeString(pid int, ptr uint64, bpfData []byte, probeRet int32, scName string, limit int) string {
	if ptr == 0 {
		return "NULL"
	}
	var raw []byte
	truncated := false
	bpfRaw, bpfFound, _, found := parseBPFData(bpfData, probeRet)

	if found {
		raw = bpfRaw
		if limit > 0 && len(raw) > limit {
			truncated = true
		} else if limit <= 0 && len(raw) == 4095 {
			// We hit the maximum capacity of the BPF buffer (4096 - 1 NUL).
			// We cannot tell if it was truncated by bpf_probe_read_user_str or if it naturally ended at 4095.
			// Fallback to MemReader to verify!
			found = false
		}
	} else {
		// BPF buffer did not contain '\0'
		if probeRet >= 0 && bpfFound {
			if limit > 0 && len(bpfRaw) >= limit {
				raw = bpfRaw
				truncated = true
				found = true
			} else if limit <= 0 && len(bpfRaw) == 4096 {
				raw = bpfRaw[:4095]
				truncated = true
				found = true
			}
		}
	}
	if !found {
		readSize := 4096
		if limit > 0 && limit < 4096 {
			readSize = limit + 1
		}
		data, err := d.MemReader.ReadRobust(pid, ptr, readSize, false)
		if err == nil {
			if idx := bytes.IndexByte(data, 0); idx != -1 {
				raw = data[:idx]
				if limit > 0 && idx > limit {
					truncated = true
				}
				found = true
			} else {
				if len(data) == readSize {
					raw = data
					truncated = true
					found = true
				} else if limit > 0 && len(data) >= limit {
					raw = data[:limit]
					truncated = true
					found = true
				} else {
					// Hit a memory fault before finding '\0'
					found = false
				}
			}
		} else {
			if probeRet >= 0 && bpfFound && len(bpfRaw) > 0 {
				raw = bpfRaw
				if limit > 0 && len(bpfRaw) > limit {
					truncated = true
				}
				found = true
			}
		}
	}

	var finalRes string
	if found {
		// IMPACT: Uses StringLimit if set as the primary truncation threshold for string arguments (limit > 0), ensuring paths (limit <= 0) bypass truncation.
		printLimit := limit
		if printLimit <= 0 {
			printLimit = 4095
		} else if d.StringLimit > 0 && d.StringLimit < printLimit {
			printLimit = d.StringLimit
		}
		actualLen := 0
		if truncated {
			actualLen = printLimit + 1
		}
		finalRes = format.BufferEscape(raw, printLimit, actualLen, d.HexEscapeMode)
	} else {
		finalRes = fmt.Sprintf("%#x", ptr)
	}

	return finalRes
}

// DecodeStringRaw decodes a string without quoting it.
func (d *Decoder) DecodeStringRaw(pid int, ptr uint64, bpfData []byte, probeRet int32) string {
	if ptr == 0 {
		return "NULL"
	}

	if len(bpfData) > 0 {
		if idx := bytes.IndexByte(bpfData, 0); idx != -1 {
			if idx > 0 || probeRet >= 0 {
				return string(bpfData[:idx])
			}
		}
	}
	if data, err := d.MemReader.ReadRobust(pid, ptr, 512, false); err == nil {
		if idx := bytes.IndexByte(data, 0); idx != -1 {
			return string(data[:idx])
		}
		if len(data) == 512 {
			return string(data)
		}
	}
	return fmt.Sprintf("%#x", ptr)
}

// MatchPath checks if the syscall matches any of the paths in the filter list.
func MatchPath(pid int, fds []int32, isPath bool, scName string, ptr uint64, rawStrArg string, tracePaths map[string]bool, fdMap map[string]string) bool {
	if len(tracePaths) == 0 {
		return true
	}

	var candidatePaths []string

	// 1. Path from FDs
	baseFd := int32(-1)
	for _, fd := range fds {
		if fd != -1 {
			if path, ok := fdMap[fmt.Sprintf("%d:%d", pid, fd)]; ok {
				candidatePaths = append(candidatePaths, path)
			}
			if baseFd == -1 {
				baseFd = fd
			}
		}
	}

	// 2. Path from string argument
	if isPath && rawStrArg != "" && rawStrArg != "NULL" && !strings.HasPrefix(rawStrArg, "0x") {
		p := rawStrArg
		if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
			p = p[1 : len(p)-1]
		}

		if strings.HasPrefix(p, "/") {
			candidatePaths = append(candidatePaths, p)
		} else {
			candidatePaths = append(candidatePaths, p)

			// resolve relative
			base := ""
			if baseFd != -1 && baseFd != -100 /* AT_FDCWD */ {
				base = fdMap[fmt.Sprintf("%d:%d", pid, baseFd)]
			} else if baseFd == -1 || baseFd == -100 {
				if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
					base = cwd
				}
			}
			if base != "" {
				candidatePaths = append(candidatePaths, base+"/"+p)
			} else {
				candidatePaths = append(candidatePaths, p)
			}
		}
	}

	// Check all candidate paths
	for _, p := range candidatePaths {
		if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
			p = p[1 : len(p)-1]
		}
		for tp := range tracePaths {
			if p == tp || strings.HasPrefix(p, tp+"/") {
				return true
			}

			absTP := tp
			if !strings.HasPrefix(tp, "/") {
				if cwd, err := os.Getwd(); err == nil {
					absTP = cwd + "/" + tp
				}
			}
			if p == absTP || strings.HasPrefix(p, absTP+"/") {
				return true
			}
		}
	}
	return false
}
