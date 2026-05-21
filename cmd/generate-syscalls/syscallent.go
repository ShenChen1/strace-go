package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// syscallentEntry holds data parsed from one line of syscallent.h.
type syscallentEntry struct {
	ID   int
	Name string
	Argc int
}

// parseSyscallent parses strace-upstream's syscallent.h file to extract
// syscall ID → (name, argc) mappings.
// Format: [  0] = { 3,    TD,             SEN(read),   "read"   },
// or: [BASE_NR + 424] = { 4,  TD|TS|TP,       SEN(pidfd_send_signal),         "pidfd_send_signal"     },
var syscallentRe = regexp.MustCompile(
	`\[\s*(?:BASE_NR\s*\+\s*)?(\d+)\]\s*=\s*\{\s*(\d+),\s*\S+,\s*SEN\(\w+\),\s*"(\w+)"`,
)

func parseSyscallent(path string) ([]syscallentEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open syscallent.h: %w", err)
	}
	defer f.Close()

	dir := filepath.Dir(path)
	var entries []syscallentEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#include \"") {
			incFile := strings.Trim(line[len("#include \""):], "\"")
			// Try relative to current file
			incPath := filepath.Join(dir, incFile)
			if _, err := os.Stat(incPath); err != nil {
				// Try generic directory as fallback for syscallent-common.h
				incPath = filepath.Join(dir, "..", "generic", incFile)
			}
			
			subEntries, err := parseSyscallent(incPath)
			if err == nil {
				entries = append(entries, subEntries...)
			}
			continue
		}

		m := syscallentRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		argc, _ := strconv.Atoi(m[2])
		name := m[3]
		entries = append(entries, syscallentEntry{ID: id, Name: name, Argc: argc})
	}
	return entries, scanner.Err()
}
