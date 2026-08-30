package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDStateStorePersistsEventFDDetails(t *testing.T) {
	store := newFDStateStore(nil)
	store.ApplyFDState(eventFDStateUpdate(7, 5, 17, 1, 0))

	want := "anon_inode:[eventfd],eventfd-count=0x5,eventfd-id=17,eventfd-semaphore=1"
	if got := store.paths["101:7"]; got != want {
		t.Fatalf("eventfd target = %q, want %q", got, want)
	}
}

func TestFDStateStoreKeepsBasePathAfterFailedEventFDSnapshot(t *testing.T) {
	store := newFDStateStore(nil)
	store.ApplyFDState(eventFDStateUpdate(7, 0, 0, 0, -14))

	if got := store.paths["101:7"]; got != "anon_inode:[eventfd]" {
		t.Fatalf("eventfd target after failed snapshot = %q", got)
	}
}

func TestFDStateStoreAddsSuccessfulEventFDWrite(t *testing.T) {
	store := newFDStateStore(map[string]string{
		"101:7": "anon_inode:[eventfd],eventfd-count=0x5,eventfd-id=17,eventfd-semaphore=0",
	})
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, 3)
	store.ApplyFDState(fdStateUpdate{
		source: fdStateSource{
			view: syscallEventView{valid: true, eventType: bpfEventTypeExit, args: [6]uint64{7}, ret: 8},
			payloadSections: []handler.PayloadSection{{
				Kind:      handler.PayloadKindBytes,
				Direction: handler.PayloadDirectionIn,
				ArgIndex:  1,
				UserLen:   8,
				CopiedLen: 8,
				ProbeRet:  0,
				Data:      data,
			}},
		},
		meta:      meta.Syscall{Name: "write"},
		targetPID: 101,
	})

	want := "anon_inode:[eventfd],eventfd-count=0x8,eventfd-id=17,eventfd-semaphore=0"
	if got := store.paths["101:7"]; got != want {
		t.Fatalf("eventfd target after write = %q, want %q", got, want)
	}
}

func eventFDStateUpdate(fd int32, count uint64, id int32, semaphore uint32, probeRet int32) fdStateUpdate {
	stateData := []byte(nil)
	if probeRet == 0 {
		stateData = eventFDStateSnapshotBytes(count, id, semaphore)
	}
	return fdStateUpdate{
		source: fdStateSource{
			view: syscallEventView{valid: true, eventType: bpfEventTypeExit, ret: int64(fd)},
			payloadSections: []handler.PayloadSection{
				{
					Kind:      handler.PayloadKindFDState,
					Direction: handler.PayloadDirectionOut,
					ArgIndex:  handler.PayloadFDStateArgIndex,
					UserLen:   handler.FDStateSnapshotSize,
					CopiedLen: handler.FDStateSnapshotSize,
					ProbeRet:  0,
					Data: fdStateSnapshotBytes(fd, handler.FDStateFlagIdentity,
						0600, 0, 0, 15, 0),
				},
				{
					Kind:      handler.PayloadKindEventFDState,
					Direction: handler.PayloadDirectionOut,
					ArgIndex:  handler.PayloadEventFDStateArgIndex,
					UserLen:   handler.EventFDStateSnapshotSize,
					CopiedLen: uint32(len(stateData)),
					ProbeRet:  probeRet,
					Data:      stateData,
				},
			},
		},
		meta:      meta.Syscall{Name: "eventfd2"},
		targetPID: 101,
	}
}
