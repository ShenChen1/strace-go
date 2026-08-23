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

func TestBPFRoutePlanSelectsSplitDirectExitFamilies(t *testing.T) {
	table := map[uint32]meta.Syscall{
		1: {Name: "read"},
		2: {Name: "stat"},
		3: {Name: "cachestat"},
		4: {Name: "epoll_wait"},
		5: {Name: "fcntl"},
		6: {Name: "getpid"},
	}
	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	want := map[uint32]uint32{
		1: exitProgFDTime,
		2: exitProgStruct,
		3: exitProgAsync,
		4: exitProgIO,
		5: exitProgControl,
		6: exitProgGeneric,
	}
	for id, expected := range want {
		if plan.exit[id] != expected {
			t.Fatalf("exit route[%d] = %d, want %d", id, plan.exit[id], expected)
		}
	}
}

func TestBPFRouteCapabilitiesKeepEnterAndExitPolicyTogether(t *testing.T) {
	capability, ok := bpfRouteCapabilities["openat2"]
	if !ok {
		t.Fatal("openat2 capability is missing")
	}
	if capability.enterSlot != enterProgOpenat2 || capability.exitSlot != exitProgPath {
		t.Fatalf("openat2 capability = %+v, want enter openat2 and exit path", capability)
	}

	capability, ok = bpfRouteCapabilities["epoll_pwait2"]
	if !ok {
		t.Fatal("epoll_pwait2 capability is missing")
	}
	if capability.enterSlot != enterProgEpoll || capability.exitSlot != exitProgIO {
		t.Fatalf("epoll_pwait2 capability = %+v, want enter epoll and exit IO", capability)
	}
}

func TestBPFRouteCapabilitiesUseBpfExitProviderForObjectInfo(t *testing.T) {
	capability, ok := bpfRouteCapabilities["bpf"]
	if !ok {
		t.Fatal("bpf capability is missing")
	}
	if capability.enterSlot != enterProgBpf || capability.exitSlot != exitProgIO {
		t.Fatalf("bpf capability = %+v, want enter bpf and exit IO", capability)
	}

	id, ok := routeSyscallIDByName(meta.SyscallTable, "bpf")
	if !ok {
		t.Fatal("bpf syscall is missing from generated table")
	}
	plan, err := newBPFRoutePlan(meta.SyscallTable)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	if plan.exit[id] != exitProgIO {
		t.Fatalf("bpf exit route = %d, want %d", plan.exit[id], exitProgIO)
	}
}

func TestPlainEnterElisionRequiresGenericEnterAndExit(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "getpid", want: true},
		{name: "read", want: false},
		{name: "openat", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := syscallIDByName(t, test.name)
			if got := isPlainGenericEnterExitRoute(id); got != test.want {
				t.Fatalf("isPlainGenericEnterExitRoute(%q) = %v, want %v", test.name, got, test.want)
			}
		})
	}
}

func TestStandaloneExitElisionRoutesAreExplicitAndNarrow(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "clock_gettime", want: true},
		{name: "clock_getres", want: true},
		{name: "gettimeofday", want: true},
		{name: "arch_prctl", want: true},
		{name: "get_robust_list", want: true},
		{name: "read", want: false},
		{name: "openat", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := syscallIDByName(t, test.name)
			if got := isStandaloneExitElisionRoute(id); got != test.want {
				t.Fatalf("isStandaloneExitElisionRoute(%q) = %v, want %v", test.name, got, test.want)
			}
		})
	}
	if !isGenericEnterRoute(syscallIDByName(t, "clock_gettime")) {
		t.Fatal("clock_gettime should keep the generic enter route")
	}
	if isGenericEnterRoute(syscallIDByName(t, "openat")) {
		t.Fatal("openat should use its specialized enter route")
	}
}

func TestBPFRoutePlanRejectsInvalidCapabilitySlot(t *testing.T) {
	table := map[uint32]meta.Syscall{
		1: {Name: "getpid"},
	}
	capabilities := map[string]bpfRouteCapability{
		"getpid": {enterSlot: 999},
	}
	if _, err := newBPFRoutePlanWithCapabilities(table, capabilities); err == nil ||
		!strings.Contains(err.Error(), "unknown BPF enter route slot 999") {
		t.Fatalf("newBPFRoutePlanWithCapabilities() error = %v, want invalid slot error", err)
	}
}

func TestBPFRoutePlanCoversSplitDirectExitCatalog(t *testing.T) {
	plan, err := newBPFRoutePlan(meta.SyscallTable)
	if err != nil {
		t.Fatalf("newBPFRoutePlan() error = %v", err)
	}
	catalog := []struct {
		slot  uint32
		names []string
	}{
		{exitProgFDTime, []string{
			"read", "pread64", "gettimeofday", "clock_gettime", "clock_getres",
			"getitimer", "setitimer", "adjtimex", "clock_adjtime", "nanosleep",
			"clock_nanosleep", "dup", "dup2", "dup3", "epoll_create", "timerfd_create",
			"eventfd", "eventfd2", "epoll_create1", "inotify_init", "inotify_init1",
			"signalfd", "signalfd4",
		}},
		{exitProgStruct, []string{
			"stat", "lstat", "fstat", "newfstatat", "statx", "statfs", "fstatfs",
			"waitid", "rt_sigaction", "rt_sigprocmask", "rt_sigsuspend", "getcwd",
			"readlink", "readlinkat", "pipe", "pipe2", "socketpair", "uname", "sysinfo",
			"getrlimit", "prlimit64",
		}},
		{exitProgAsync, []string{
			"sendfile", "arch_prctl", "get_robust_list", "cachestat", "capget", "capset",
			"prctl", "io_getevents", "io_pgetevents", "io_setup", "poll", "ppoll",
		}},
		{exitProgIO, []string{
			"select", "pselect6", "epoll_wait", "epoll_pwait", "epoll_pwait2", "getdents", "getdents64",
			"execve", "execveat", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
			"llistxattr", "flistxattr",
		}},
		{exitProgControl, []string{
			"fcntl", "ioctl", "connect", "bind", "sendto", "recvfrom", "accept", "accept4",
			"getsockname", "getpeername", "setsockopt", "getsockopt",
		}},
	}
	for _, family := range catalog {
		for _, name := range family.names {
			id, ok := routeSyscallIDByName(meta.SyscallTable, name)
			if !ok {
				t.Fatalf("split exit catalog syscall %q is missing from generated table", name)
			}
			if plan.exit[id] != family.slot {
				t.Fatalf("exit route for %s = %d, want family slot %d", name, plan.exit[id], family.slot)
			}
		}
	}
}

func routeSyscallIDByName(table map[uint32]meta.Syscall, name string) (uint32, bool) {
	for id, syscall := range table {
		if syscall.Name == name {
			return id, true
		}
	}
	return 0, false
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

func TestBPFRouteProgramsUseHandlerCapability(t *testing.T) {
	enter := &ebpf.Program{}
	exit := &ebpf.Program{}
	catalog := newBPFProgramCatalog(nil, map[string]*ebpf.Program{
		"enter_no_payload_direct": enter,
		"exit_generic":            exit,
	})

	enterPrograms := routePrograms(enterProgArrayEntries(catalog))
	if enterPrograms[enterProgNoPayload] != enter {
		t.Fatal("enter route catalog did not expose the handler capability")
	}
	exitPrograms := routePrograms(exitProgArrayEntries(catalog))
	if exitPrograms[exitProgGeneric] != exit {
		t.Fatal("exit route catalog did not expose the handler capability")
	}
}
