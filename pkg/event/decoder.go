package event

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"strace-go/pkg/format"
)

// IMPACT: Added StringLimit field to Decoder to allow DecodeString to apply command-line formatting limits independently from internal buffer size limits.
type Decoder struct {
	HexEscapeMode int
	StringLimit   int
}

func NewDecoder() *Decoder {
	return &Decoder{HexEscapeMode: 0}
}

// IMPACT: DecodeString is snapshot-only; partial BPF bytes are decoded only when
// the probe result proves the captured prefix is usable.
// parseBPFData extracts string raw data from BPF buffer.
func parseBPFData(bpfData []byte, probeRet int32) (bpfRaw []byte, bpfFound bool, raw []byte, found bool) {
	if len(bpfData) == 0 {
		return nil, false, nil, false
	}
	idx := bytes.IndexByte(bpfData, 0)
	if idx != -1 {
		bpfRaw = bpfData[:idx]
		bpfFound = true
		// If null terminator is at the very last byte, it may be a BPF buffer boundary marker.
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

// DecodeString decodes a string from BPF-captured bytes only.
func (d *Decoder) DecodeString(_ int, ptr uint64, bpfData []byte, probeRet int32, _ string, limit int) string {
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
func (d *Decoder) DecodeStringRaw(_ int, ptr uint64, bpfData []byte, probeRet int32) string {
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
	return fmt.Sprintf("%#x", ptr)
}

// PathArgument binds one probe-site pathname snapshot to its directory fd.
type PathArgument struct {
	Text  string
	DirFD int32
}

// PathMatchRequest carries the state needed to evaluate a -P path filter.
type PathMatchRequest struct {
	Pid           int
	FDs           []int32
	PathArguments []PathArgument
	TracePaths    map[string]bool
	FDMap         map[string]string
}

// MatchPath checks if the syscall matches any of the paths in the filter list.
func MatchPath(req PathMatchRequest) bool {
	if len(req.TracePaths) == 0 {
		return true
	}

	candidatePaths := fdCandidatePaths(req.Pid, req.FDs, req.FDMap)
	for _, pathArg := range req.PathArguments {
		candidatePaths = append(candidatePaths, pathArgumentCandidates(req.Pid, pathArg, req.FDMap)...)
	}
	return anyCandidateMatchesTracePath(candidatePaths, req.TracePaths)
}

func fdCandidatePaths(pid int, fds []int32, fdMap map[string]string) []string {
	candidatePaths := []string{}
	for _, fd := range fds {
		if fd == -1 {
			continue
		}
		// IMPACT: the event-driven fdMap is authoritative because fd-state
		// syscalls flow through the BPF runtime even when filtered from output;
		// /proc is only a fallback for fd mutations the tracker does not cover.
		if path, ok := fdMap[fdMapKey(pid, fd)]; ok {
			candidatePaths = append(candidatePaths, path)
		} else if path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd)); err == nil {
			candidatePaths = append(candidatePaths, path)
			if fdMap != nil {
				fdMap[fdMapKey(pid, fd)] = path
			}
		}
	}
	return candidatePaths
}

func pathArgumentCandidates(pid int, pathArg PathArgument, fdMap map[string]string) []string {
	if !usablePathArgument(pathArg) {
		return nil
	}
	path := unquotePath(pathArg.Text)
	if strings.HasPrefix(path, "/") {
		return []string{path}
	}

	candidates := []string{path}
	base := relativePathBase(pid, pathArg.DirFD, fdMap)
	if base != "" {
		candidates = append(candidates, base+"/"+path)
	} else {
		candidates = append(candidates, path)
	}
	return candidates
}

func usablePathArgument(pathArg PathArgument) bool {
	return pathArg.Text != "" &&
		pathArg.Text != "NULL" &&
		!strings.HasPrefix(pathArg.Text, "0x")
}

func relativePathBase(pid int, baseFd int32, fdMap map[string]string) string {
	if baseFd != -1 && baseFd != -100 {
		return fdMap[fdMapKey(pid, baseFd)]
	}
	if baseFd == -1 || baseFd == -100 {
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
			return cwd
		}
	}
	return ""
}

func anyCandidateMatchesTracePath(candidatePaths []string, tracePaths map[string]bool) bool {
	for _, candidate := range candidatePaths {
		path := unquotePath(candidate)
		for tracePath := range tracePaths {
			if pathMatchesTracePath(path, tracePath) {
				return true
			}
		}
	}
	return false
}

func pathMatchesTracePath(path string, tracePath string) bool {
	if path == tracePath || strings.HasPrefix(path, tracePath+"/") {
		return true
	}
	absTracePath := tracePath
	if !strings.HasPrefix(tracePath, "/") {
		if cwd, err := os.Getwd(); err == nil {
			absTracePath = cwd + "/" + tracePath
		}
	}
	return path == absTracePath || strings.HasPrefix(path, absTracePath+"/")
}

func unquotePath(path string) string {
	if len(path) >= 2 && path[0] == '"' && path[len(path)-1] == '"' {
		return path[1 : len(path)-1]
	}
	return path
}

func fdMapKey(pid int, fd int32) string {
	return fmt.Sprintf("%d:%d", pid, fd)
}
