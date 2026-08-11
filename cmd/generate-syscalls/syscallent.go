package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// syscallentEntry holds semantic metadata parsed from one line of syscallent.h.
// ID is retained by the parser but replaced by the local ABI number during merge.
type syscallentEntry struct {
	ID    int
	Name  string
	Argc  int
	Flags string
}

// parseSyscallent parses strace-upstream's syscallent.h file to extract
// semantic name, ABI arity, and formatter flags. The parsed ID is not authoritative.
// Format: [  0] = { 3,    TD,             SEN(read),   "read"   },
// or: [BASE_NR + 424] = { 4,  TD|TS|TP,       SEN(pidfd_send_signal),         "pidfd_send_signal"     },
var syscallentRe = regexp.MustCompile(
	`\[\s*(?:BASE_NR\s*\+\s*)?(\d+)\]\s*=\s*\{\s*(\d+),\s*([A-Za-z0-9_|]+),\s*SEN\(\w+\),\s*"(\w+)"`,
)

type syscallentParser struct{}

func parseSyscallent(path string) ([]syscallentEntry, error) {
	return syscallentParser{}.ParseFile(path)
}

func (p syscallentParser) ParseFile(path string) ([]syscallentEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open syscallent.h: %w", err)
	}
	defer f.Close()

	entries, err := p.Parse(f, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return entries, nil
}

func (p syscallentParser) Parse(r io.Reader, dir string) ([]syscallentEntry, error) {
	var entries []syscallentEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#include \"") {
			incPath, err := p.resolveInclude(dir, line)
			if err != nil {
				return nil, err
			}
			subEntries, err := p.ParseFile(incPath)
			if err != nil {
				return nil, err
			}
			entries = append(entries, subEntries...)
			continue
		}

		m := syscallentRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		argc, _ := strconv.Atoi(m[2])
		entries = append(entries, syscallentEntry{
			ID:    id,
			Name:  m[4],
			Argc:  argc,
			Flags: m[3],
		})
	}
	return entries, scanner.Err()
}

func (syscallentParser) resolveInclude(dir string, line string) (string, error) {
	incFile := strings.Trim(line[len("#include \""):], "\"")
	candidates := []string{
		filepath.Join(dir, incFile),
		filepath.Join(dir, "..", "generic", incFile),
	}
	for _, candidate := range candidates {
		if isFile(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("resolve include %q from %s", incFile, dir)
}
