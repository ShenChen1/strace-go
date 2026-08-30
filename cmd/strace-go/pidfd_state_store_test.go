package main

import (
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestFDStateStorePersistsPIDFDTarget(t *testing.T) {
	store := newFDStateStore(nil)
	store.ApplyFDState(pidFDStateUpdate(7, 1234, 0))

	if got := store.paths["101:7"]; got != "anon_inode:[pidfd],pid=1234" {
		t.Fatalf("pidfd target = %q", got)
	}
	if !store.fdCloexec["101:7"] {
		t.Fatal("pidfd CLOEXEC state was not persisted")
	}
}

func TestFDStateStoreSkipsFailedPIDFDOpen(t *testing.T) {
	store := newFDStateStore(nil)
	store.ApplyFDState(pidFDStateUpdate(-1, 1234, 0))

	if len(store.paths) != 0 || len(store.fdCloexec) != 0 {
		t.Fatalf("failed pidfd_open stored state: paths=%v cloexec=%v", store.paths, store.fdCloexec)
	}
}

func pidFDStateUpdate(fd int32, pid uint32, flags uint32) fdStateUpdate {
	sections := []handler.PayloadSection(nil)
	if fd >= 0 {
		sections = []handler.PayloadSection{{
			Kind:      handler.PayloadKindFDState,
			Direction: handler.PayloadDirectionOut,
			ArgIndex:  handler.PayloadFDStateArgIndex,
			UserLen:   handler.FDStateSnapshotSize,
			CopiedLen: handler.FDStateSnapshotSize,
			ProbeRet:  0,
			Data: fdStateSnapshotBytes(fd, handler.FDStateFlagIdentity,
				0600, 0, 0, 15, 0),
		}}
	}
	return fdStateUpdate{
		source: fdStateSource{
			view: syscallEventView{
				valid: true,
				args:  [6]uint64{uint64(pid), uint64(flags)},
				ret:   int64(fd),
			},
			payloadSections: sections,
		},
		meta:      meta.Syscall{Name: "pidfd_open"},
		targetPID: 101,
	}
}
