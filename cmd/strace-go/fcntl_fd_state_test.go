package main

import (
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDStateStorePersistsFcntlDupObservationsAndOffsets(t *testing.T) {
	for _, command := range []uint64{0, 1030} {
		t.Run(fcntlCommandName(command), func(t *testing.T) {
			store := newFDStateStoreFromMaps(
				map[string]string{"101:5": "/dev/null", "101:12": "/tmp/old"},
				map[string]int64{"101:5": 17, "101:12": 99},
			)
			store.fdStates["101:12"] = handler.FDStateObservation{FD: 12, Inode: 99}
			ev := syscallEventContext{
				view: syscallEventView{
					valid: true,
					args:  [6]uint64{5, command, 20},
					ret:   12,
				},
				statePID: 101,
				meta:     meta.Syscall{Name: "fcntl"},
				payloadSections: []handler.PayloadSection{fdStatePayloadSection(
					fdStateSnapshotBytes(
						12, handler.FDStateFlagIdentity|handler.FDStateFlagOffset,
						0100644, 1, 2, 3, 17,
					),
				)},
			}

			ev.updateFDState(store)
			ev.updateFDOffsets(store)

			observation, ok := store.fdStates["101:12"]
			if !ok || observation.Inode != 3 || observation.Offset != 17 {
				t.Fatalf("fcntl observation = %+v, ok=%v", observation, ok)
			}
			if got := store.paths["101:12"]; got != "/dev/null" {
				t.Fatalf("fcntl target path = %q, want /dev/null", got)
			}
			if got := store.offsets["101:12"]; got != 17 {
				t.Fatalf("fcntl target offset = %d, want 17", got)
			}
		})
	}
}

func TestFDStateStoreFcntlDupFailureClearsTarget(t *testing.T) {
	store := newFDStateStoreFromMaps(
		map[string]string{"101:5": "/dev/null", "101:12": "/tmp/old"},
		map[string]int64{"101:5": 17, "101:12": 99},
	)
	store.fdStates["101:5"] = handler.FDStateObservation{FD: 5, Inode: 3, Offset: 17}
	store.fdStates["101:12"] = handler.FDStateObservation{FD: 12, Inode: 99}
	ev := syscallEventContext{
		view: syscallEventView{
			valid: true,
			args:  [6]uint64{5, 0, 20},
			ret:   12,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "fcntl"},
		payloadSections: []handler.PayloadSection{{
			Kind:      handler.PayloadKindFDState,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  handler.PayloadFDStateArgIndex,
			UserLen:   handler.FDStateSnapshotSize,
			ProbeRet:  -14,
		}},
	}

	ev.updateFDState(store)
	ev.updateFDOffsets(store)

	if _, ok := store.fdStates["101:12"]; ok {
		t.Fatal("failed fcntl duplication retained target observation")
	}
	if _, ok := store.paths["101:12"]; ok {
		t.Fatal("failed fcntl duplication retained target path")
	}
	if _, ok := store.offsets["101:12"]; ok {
		t.Fatal("failed fcntl duplication retained target offset")
	}
	if got := store.paths["101:5"]; got != "/dev/null" {
		t.Fatalf("failed fcntl duplication changed source path = %q", got)
	}
	if got := store.offsets["101:5"]; got != 17 {
		t.Fatalf("failed fcntl duplication changed source offset = %d", got)
	}
}

func TestFDStateStoreFcntlGetterDoesNotCreateObservation(t *testing.T) {
	store := newFDStateStoreFromMaps(nil, nil)
	ev := syscallEventContext{
		view: syscallEventView{
			valid: true,
			args:  [6]uint64{5, 3, 0},
			ret:   32768,
		},
		statePID: 101,
		meta:     meta.Syscall{Name: "fcntl"},
		payloadSections: []handler.PayloadSection{fdStatePayloadSection(
			fdStateSnapshotBytes(32768, handler.FDStateFlagIdentity, 0, 0, 0, 3, 0),
		)},
	}

	ev.updateFDState(store)

	if len(store.fdStates) != 0 {
		t.Fatalf("getter created FD state: %+v", store.fdStates)
	}
}

func fcntlCommandName(command uint64) string {
	if command == 1030 {
		return "F_DUPFD_CLOEXEC"
	}
	return "F_DUPFD"
}
