package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

func TestBPFRoutePlanUsesGenericDefaults(t *testing.T) {
	table := map[uint32]meta.Syscall{
		10: {Name: "getpid"},
		11: {Name: "unknown"},
	}

	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	for id := range table {
		if got := plan.enter[id]; got != enterProgNoPayload {
			t.Fatalf("enter route[%d] = %d, want generic %d", id, got, enterProgNoPayload)
		}
		if got := plan.exit[id]; got != exitProgGeneric {
			t.Fatalf("exit route[%d] = %d, want generic %d", id, got, exitProgGeneric)
		}
	}
}

func TestBPFRoutePlanSelectsSpecializedFamilies(t *testing.T) {
	table := map[uint32]meta.Syscall{
		1: {Name: "write"},
		2: {Name: "readv"},
		3: {Name: "sendmsg"},
		4: {Name: "recvmmsg"},
		5: {Name: "move_mount"},
	}

	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	want := map[uint32]struct {
		enter uint32
		exit  uint32
	}{
		1: {enter: enterProgPayload, exit: exitProgGeneric},
		2: {enter: enterProgIovec, exit: exitProgIovecBase},
		3: {enter: enterProgMsg, exit: exitProgMsg},
		4: {enter: enterProgMmsg, exit: exitProgRecvmmsgBase01},
		5: {enter: enterProgMountPath, exit: exitProgGeneric},
	}
	for id, expected := range want {
		if plan.enter[id] != expected.enter || plan.exit[id] != expected.exit {
			t.Fatalf("route[%d] = (%d, %d), want (%d, %d)", id, plan.enter[id], plan.exit[id], expected.enter, expected.exit)
		}
	}
}

func TestBPFRoutePlanCoversGeneratedSyscalls(t *testing.T) {
	plan, err := newBPFRoutePlan(meta.SyscallTable)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	if len(plan.enter) != len(meta.SyscallTable) || len(plan.exit) != len(meta.SyscallTable) {
		t.Fatalf("route sizes = (%d, %d), want (%d, %d)", len(plan.enter), len(plan.exit), len(meta.SyscallTable), len(meta.SyscallTable))
	}
	for id := range meta.SyscallTable {
		if _, ok := plan.enter[id]; !ok {
			t.Fatalf("missing enter route for syscall %d", id)
		}
		if _, ok := plan.exit[id]; !ok {
			t.Fatalf("missing exit route for syscall %d", id)
		}
	}
}

func TestBPFRoutePlanRejectsUnsupportedSyscallID(t *testing.T) {
	_, err := newBPFRoutePlan(map[uint32]meta.Syscall{
		bpfRouteMapMaxEntries: {Name: "too_large"},
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds BPF route map capacity") {
		t.Fatalf("newBPFRoutePlan() error = %v, want capacity error", err)
	}
}

func TestBPFRoutePlanRejectsDuplicateSyscallName(t *testing.T) {
	_, err := newBPFRoutePlan(map[uint32]meta.Syscall{
		1: {Name: "duplicate"},
		2: {Name: "duplicate"},
	})
	if err == nil || !strings.Contains(err.Error(), `syscall name "duplicate" has ids`) {
		t.Fatalf("newBPFRoutePlan() error = %v, want duplicate name error", err)
	}
}

func TestPutBPFRouteEntriesSortsAndPropagatesWriterFailure(t *testing.T) {
	first := &ebpf.Program{}
	second := &ebpf.Program{}
	writer := &fakeProgArrayWriter{failAt: 1, failErr: errors.New("route map update failed")}
	routes := map[uint32]uint32{9: 2, 3: 1, 7: 1}
	programs := map[uint32]*ebpf.Program{1: first, 2: second}

	err := putBPFRouteEntries("enter_routes", writer, routes, programs)
	if err == nil || !strings.Contains(err.Error(), "enter_routes[7]: route map update failed") {
		t.Fatalf("putBPFRouteEntries() error = %v, want indexed writer error", err)
	}
	if len(writer.writes) != 2 {
		t.Fatalf("writes = %d, want 2 after writer failure", len(writer.writes))
	}
	if writer.writes[0].index != 3 || writer.writes[1].index != 7 {
		t.Fatalf("write order = (%d, %d), want (3, 7)", writer.writes[0].index, writer.writes[1].index)
	}
}
