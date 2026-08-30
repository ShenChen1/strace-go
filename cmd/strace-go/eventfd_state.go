package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

const (
	eventFDTargetPrefix = "anon_inode:[eventfd],"
	maxEventFDCount     = ^uint64(0) - 1
)

func updateEventFDMapFromSource(
	src fdStateSource,
	scMeta meta.Syscall,
	targetPID int,
	paths map[string]string,
) {
	if !src.view.valid || src.view.ret < 0 ||
		(scMeta.Name != "eventfd" && scMeta.Name != "eventfd2") {
		return
	}
	state, ok := eventFDStateFromSections(src.payloadSections)
	if !ok {
		return
	}
	fd := int32(src.view.ret)
	paths[fdStateKey(targetPID, fd)] = eventFDStateTarget(state)
}

func eventFDStateFromSections(sections []handler.PayloadSection) (handler.EventFDState, bool) {
	for _, section := range sections {
		if section.Kind != handler.PayloadKindEventFDState ||
			section.Direction != handler.PayloadDirectionOut ||
			section.ArgIndex != handler.PayloadEventFDStateArgIndex ||
			section.UserLen != handler.EventFDStateSnapshotSize ||
			section.CopiedLen < handler.EventFDStateSnapshotSize ||
			section.ProbeRet != 0 {
			continue
		}
		return handler.DecodeEventFDState(section.Data)
	}
	return handler.EventFDState{}, false
}

func eventFDStateTarget(state handler.EventFDState) string {
	return fmt.Sprintf(
		"anon_inode:[eventfd],eventfd-count=%s,eventfd-id=%d,eventfd-semaphore=%d",
		formatEventFDStateCount(state.Count), state.ID, state.Semaphore,
	)
}

func updateEventFDCountFromSource(
	src fdStateSource,
	scMeta meta.Syscall,
	targetPID int,
	paths map[string]string,
) {
	if !src.view.valid || src.view.ret != 8 ||
		(scMeta.Name != "read" && scMeta.Name != "write") {
		return
	}
	key := fdStateKey(targetPID, int32(src.view.args[0]))
	target, ok := paths[key]
	if !ok {
		return
	}
	count, valueStart, valueEnd, ok := eventFDCountFromTarget(target)
	if !ok {
		return
	}
	count, ok = eventFDCountAfterIO(src, scMeta.Name, target, count)
	if !ok {
		return
	}
	paths[key] = target[:valueStart] + formatEventFDStateCount(count) + target[valueEnd:]
}

func eventFDCountFromTarget(target string) (uint64, int, int, bool) {
	const prefix = "eventfd-count="
	if !strings.HasPrefix(target, eventFDTargetPrefix) {
		return 0, 0, 0, false
	}
	prefixStart := strings.Index(target, prefix)
	if prefixStart < 0 {
		return 0, 0, 0, false
	}
	valueStart := prefixStart + len(prefix)
	valueEnd := len(target)
	if comma := strings.IndexByte(target[valueStart:], ','); comma >= 0 {
		valueEnd = valueStart + comma
	}
	count, err := strconv.ParseUint(target[valueStart:valueEnd], 0, 64)
	return count, valueStart, valueEnd, err == nil
}

func eventFDCountAfterIO(src fdStateSource, name, target string, count uint64) (uint64, bool) {
	if name == "read" {
		if strings.Contains(target, "eventfd-semaphore=1") && count > 0 {
			return count - 1, true
		}
		return 0, true
	}
	value, ok := eventFDWriteValue(src.payloadSections)
	if !ok || maxEventFDCount-count < value {
		return 0, false
	}
	return count + value, true
}

func eventFDWriteValue(sections []handler.PayloadSection) (uint64, bool) {
	for _, section := range sections {
		if section.Kind != handler.PayloadKindBytes ||
			section.Direction != handler.PayloadDirectionIn ||
			section.ArgIndex != 1 || section.UserLen != 8 ||
			section.CopiedLen < 8 || section.ProbeRet != 0 || len(section.Data) < 8 {
			continue
		}
		return binary.LittleEndian.Uint64(section.Data[:8]), true
	}
	return 0, false
}

func formatEventFDStateCount(count uint64) string {
	if count == 0 {
		return "0"
	}
	return fmt.Sprintf("0x%x", count)
}
