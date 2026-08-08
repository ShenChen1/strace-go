package handler

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// EventfdInfo formats eventfd metadata from fdinfo. The last observed id is
// session-scoped so a closed fd cannot affect another trace session.
func (r *Runtime) EventfdInfo(linkPath string, initialCount uint64, flags uint64, forceCount bool) string {
	fdinfoPath := strings.Replace(linkPath, "/fd/", "/fdinfo/", 1)
	file, err := os.Open(fdinfoPath)
	if err != nil {
		if r != nil && forceCount && r.lastEventfdID != -1 {
			r.lastEventfdID++
			semStr := "0"
			if flags&1 != 0 {
				semStr = "1"
			}
			return fmt.Sprintf("{eventfd-count=%#x, eventfd-id=%d, eventfd-semaphore=%s}", uint32(initialCount), r.lastEventfdID, semStr)
		}
		return ""
	}
	defer file.Close()

	var countStr string
	var inoStr string
	semStr := "0"
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "eventfd-count":
			countStr = val
		case "eventfd-id", "ino":
			inoStr = val
		case "flags":
			if f, parseErr := strconv.ParseUint(val, 8, 64); parseErr == nil && f&1 != 0 {
				semStr = "1"
			}
		}
	}
	if forceCount {
		countStr = fmt.Sprintf("%d", uint32(initialCount))
	}
	if countStr == "" || inoStr == "" {
		return ""
	}
	if id, parseErr := strconv.Atoi(inoStr); parseErr == nil && r != nil {
		r.lastEventfdID = id
	}
	cVal, _ := strconv.ParseUint(countStr, 10, 64)
	if cVal > 0 {
		countStr = fmt.Sprintf("%#x", cVal)
	}
	return fmt.Sprintf("{eventfd-count=%s, eventfd-id=%s, eventfd-semaphore=%s}", countStr, inoStr, semStr)
}
