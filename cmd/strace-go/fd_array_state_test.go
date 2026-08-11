package main

import (
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDStateStorePersistsPipeArrayObservationsAndOffsets(t *testing.T) {
	for _, syscallName := range []string{"pipe", "pipe2", "socketpair"} {
		t.Run(syscallName, func(t *testing.T) {
			store := newFDStateStoreFromMaps(nil, nil)
			ev := syscallEventContext{
				view: syscallEventView{
					valid:     true,
					eventType: bpfEventTypeExit,
					ret:       0,
				},
				statePID: 101,
				meta:     meta.Syscall{Name: syscallName},
				payloadSections: []handler.PayloadSection{
					fdStatePayloadSection(fdStateSnapshotBytes(
						7, handler.FDStateFlagIdentity|handler.FDStateFlagOffset,
						0100644, 1, 2, 3, 17,
					)),
					fdStatePayloadSection(fdStateSnapshotBytes(
						8, handler.FDStateFlagIdentity|handler.FDStateFlagOffset,
						0100600, 4, 5, 6, 23,
					)),
				},
			}

			ev.updateFDState(store)
			ev.updateFDOffsets(store)

			for _, want := range []struct {
				fd     int32
				inode  uint64
				offset int64
			}{
				{fd: 7, inode: 3, offset: 17},
				{fd: 8, inode: 6, offset: 23},
			} {
				key := fdStateKey(101, want.fd)
				observation, ok := store.fdStates[key]
				if !ok || observation.Inode != want.inode || observation.Offset != want.offset {
					t.Fatalf("observation[%s] = %+v, ok=%v", key, observation, ok)
				}
				if got := store.offsets[key]; got != want.offset {
					t.Fatalf("offset[%s] = %d, want %d", key, got, want.offset)
				}
			}
		})
	}
}

func TestFDStateStoreKeepsValidPipeObservationWhenOtherSnapshotFails(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	ev := syscallEventContext{
		view: syscallEventView{
			valid:     true,
			eventType: bpfEventTypeExit,
			ret:       0,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "pipe"},
		payloadSections: []handler.PayloadSection{
			fdStatePayloadSection(fdStateSnapshotBytes(
				7, handler.FDStateFlagIdentity, 0100644, 1, 2, 3, 0,
			)),
			{
				Kind:      handler.PayloadKindFDState,
				Direction: handler.PayloadDirectionOut,
				ArgIndex:  handler.PayloadFDStateArgIndex,
				UserLen:   handler.FDStateSnapshotSize,
				ProbeRet:  -14,
			},
		},
	}

	ev.updateFDState(store)

	if _, ok := store.fdStates[fdStateKey(101, 7)]; !ok {
		t.Fatal("valid pipe snapshot was not retained")
	}
	if len(store.fdStates) != 1 {
		t.Fatalf("FD state map size = %d, want 1", len(store.fdStates))
	}
}

func fdStatePayloadSection(data []byte) handler.PayloadSection {
	return handler.PayloadSection{
		Kind:      handler.PayloadKindFDState,
		Direction: handler.PayloadDirectionOut,
		ArgIndex:  handler.PayloadFDStateArgIndex,
		UserLen:   handler.FDStateSnapshotSize,
		CopiedLen: handler.FDStateSnapshotSize,
		ProbeRet:  0,
		Data:      data,
	}
}
