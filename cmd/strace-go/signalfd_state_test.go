package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
	"strace-go/pkg/handler"
)

func TestSignalFDCreatorPoliciesUseEventTimeMask(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		ret      int64
		mask     uint64
		wantPath string
		wantClo  bool
	}{
		{
			name:     "signalfd",
			args:     [6]uint64{^uint64(0), 0x1000, 8},
			ret:      7,
			mask:     1 << 11,
			wantPath: "signalfd:[USR2]",
		},
		{
			name:     "signalfd4",
			args:     [6]uint64{^uint64(0), 0x1000, 8, unix.O_CLOEXEC},
			ret:      8,
			mask:     1<<11 | 1<<16,
			wantPath: "signalfd:[USR2 CHLD]",
			wantClo:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []handler.PayloadSection{
				signalMaskPayloadSection(test.mask),
				fdStatePayloadSection(fdStateSnapshotBytes(
					int32(test.ret), handler.FDStateFlagIdentity|handler.FDStateFlagOffset,
					0100600, 1, 2, uint64(test.ret)+100, 37,
				)),
			}
			event := newFDStateEvent(test.name, test.args, test.ret, payload)
			policy, ok := fdCreatorPolicyFor(test.name, event.view)
			if !ok {
				t.Fatalf("missing signalfd policy for %s", test.name)
			}
			state := policy.state(fdStateSource{view: event.view, payloadSections: payload})
			if !state.pathKnown || state.path != test.wantPath {
				t.Fatalf("signalfd state = %+v, want path %q", state, test.wantPath)
			}
			if state.cloexec != test.wantClo || !state.cloexecKnown {
				t.Fatalf("signalfd cloexec state = %+v", state)
			}

			store := newFDStateStoreFromMaps(nil, nil)
			event.updateFDState(store)
			event.updateFDOffsets(store)
			key := fdStateKey(101, int32(test.ret))
			if got := store.paths[key]; got != test.wantPath {
				t.Fatalf("signalfd path = %q, want %q", got, test.wantPath)
			}
			if got := store.offsets[key]; got != 37 {
				t.Fatalf("signalfd offset = %d, want 37", got)
			}
			if got := store.fdCloexec[key]; got != test.wantClo {
				t.Fatalf("signalfd cloexec = %v, want %v", got, test.wantClo)
			}
		})
	}
}

func TestSignalFDUpdateReplacesExistingMaskPath(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:7": "signalfd:[USR2]"}, nil)
	first := newFDStateEvent(
		"signalfd",
		[6]uint64{7, 0x1000, 8},
		7,
		[]handler.PayloadSection{
			signalMaskPayloadSection(1 << 11),
			fdStatePayloadSection(fdStateSnapshotBytes(7, handler.FDStateFlagIdentity, 0100600, 1, 2, 3, 0)),
		},
	)
	first.updateFDState(store)

	updated := newFDStateEvent(
		"signalfd",
		[6]uint64{7, 0x2000, 8},
		7,
		[]handler.PayloadSection{
			signalMaskPayloadSection(1<<11 | 1<<16),
			fdStatePayloadSection(fdStateSnapshotBytes(7, handler.FDStateFlagIdentity, 0100600, 1, 2, 4, 0)),
		},
	)
	updated.updateFDState(store)

	if got := store.paths["101:7"]; got != "signalfd:[USR2 CHLD]" {
		t.Fatalf("updated signalfd path = %q", got)
	}
}

func TestSignalFDMaskUpdatePreservesExistingCloexec(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:7": "signalfd:[USR2]"}, nil)
	store.fdCloexec["101:7"] = true
	event := newFDStateEvent(
		"signalfd",
		[6]uint64{7, 0x1000, 8},
		7,
		[]handler.PayloadSection{
			signalMaskPayloadSection(1<<11 | 1<<16),
			fdStatePayloadSection(fdStateSnapshotBytes(7, handler.FDStateFlagIdentity, 0100600, 1, 2, 4, 0)),
		},
	)
	event.updateFDState(store)

	if got, ok := store.fdCloexec["101:7"]; !ok || !got {
		t.Fatalf("signalfd mask update cloexec = %v, %v; want true, true", got, ok)
	}
}

func TestSignalFDMissingMaskClearsOldPathButKeepsSnapshot(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:7": "signalfd:[USR2]"}, nil)
	event := newFDStateEvent(
		"signalfd",
		[6]uint64{7, 0x1000, 8},
		7,
		[]handler.PayloadSection{
			fdStatePayloadSection(fdStateSnapshotBytes(7, handler.FDStateFlagIdentity, 0100600, 1, 2, 5, 0)),
		},
	)
	event.updateFDState(store)

	if _, ok := store.paths["101:7"]; ok {
		t.Fatal("stale signalfd mask path survived missing enter snapshot")
	}
	if _, ok := store.fdStates["101:7"]; !ok {
		t.Fatal("valid signalfd snapshot was discarded with missing mask")
	}
}

func TestSignalFDFailedCallPreservesExistingState(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:7": "signalfd:[USR2]"}, nil)
	store.fdStates["101:7"] = handler.FDStateObservation{FD: 7, Inode: 3}
	event := newFDStateEvent("signalfd", [6]uint64{7, 0x1000, 8}, -14, nil)
	event.updateFDState(store)

	if got := store.paths["101:7"]; got != "signalfd:[USR2]" {
		t.Fatalf("failed signalfd path = %q", got)
	}
	if _, ok := store.fdStates["101:7"]; !ok {
		t.Fatal("failed signalfd call removed existing snapshot")
	}
}

func signalMaskPayloadSection(mask uint64) handler.PayloadSection {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, mask)
	return handler.PayloadSection{
		Kind:      handler.PayloadKindStruct,
		Direction: handler.PayloadDirectionIn,
		ArgIndex:  1,
		UserPtr:   0x1000,
		UserLen:   8,
		CopiedLen: 8,
		ProbeRet:  0,
		Data:      data,
	}
}
