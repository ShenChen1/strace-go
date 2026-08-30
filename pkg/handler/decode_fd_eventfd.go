package handler

import (
	"fmt"
	"strconv"
	"strings"
)

const eventFDPath = "anon_inode:[eventfd]"

func decodeEventFDTarget(target string) (string, string, bool) {
	if target == eventFDPath {
		return eventFDPath, "", true
	}
	prefix := eventFDPath + ","
	if !strings.HasPrefix(target, prefix) {
		return "", "", false
	}
	fields := strings.Split(strings.TrimPrefix(target, prefix), ",")
	if len(fields) != 3 {
		return eventFDPath, "", true
	}
	count, countOK := parseEventFDCount(fields[0])
	id, idOK := parseEventFDID(fields[1])
	semaphore, semaphoreOK := parseEventFDSemaphore(fields[2])
	if !countOK || !idOK || !semaphoreOK {
		return eventFDPath, "", true
	}
	details := fmt.Sprintf(
		"{eventfd-count=%s, eventfd-id=%d, eventfd-semaphore=%d}",
		formatEventFDCount(count), id, semaphore,
	)
	return eventFDPath, details, true
}

func parseEventFDCount(field string) (uint64, bool) {
	value, ok := strings.CutPrefix(field, "eventfd-count=")
	if !ok {
		return 0, false
	}
	count, err := strconv.ParseUint(value, 0, 64)
	return count, err == nil
}

func parseEventFDID(field string) (int32, bool) {
	value, ok := strings.CutPrefix(field, "eventfd-id=")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(value, 10, 32)
	return int32(id), err == nil && id >= 0
}

func parseEventFDSemaphore(field string) (uint32, bool) {
	value, ok := strings.CutPrefix(field, "eventfd-semaphore=")
	if !ok || (value != "0" && value != "1") {
		return 0, false
	}
	return uint32(value[0] - '0'), true
}

func formatEventFDCount(count uint64) string {
	if count == 0 {
		return "0"
	}
	return fmt.Sprintf("0x%x", count)
}
