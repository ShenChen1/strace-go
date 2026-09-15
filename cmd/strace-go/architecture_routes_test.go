package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"

	"strace-go/pkg/meta"
)

func architectureTableForTest(t testing.TB, target string) map[uint32]meta.Syscall {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../pkg/meta/syscall_table_"+target+".go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?m)^\s*(\d+): \{Name: "([a-z0-9_]+)"`).FindAllStringSubmatch(string(data), -1)
	if len(rows) < 300 {
		t.Fatalf("incomplete %s metadata: %d rows", target, len(rows))
	}
	table := make(map[uint32]meta.Syscall, len(rows))
	for _, row := range rows {
		id, err := strconv.ParseUint(row[1], 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := table[uint32(id)]; exists {
			t.Fatalf("duplicate %s syscall id %d", target, id)
		}
		table[uint32(id)] = meta.Syscall{Name: row[2]}
	}
	return table
}

func TestAMD64DispatchRoutes(t *testing.T) { checkArchitectureRoutes(t, "amd64", 0) }
func TestARM64DispatchRoutes(t *testing.T) { checkArchitectureRoutes(t, "arm64", 1) }

func checkArchitectureRoutes(t *testing.T, target string, index int) {
	t.Helper()
	table := architectureTableForTest(t, target)
	plan, err := newBPFRoutePlan(table)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		ids         [2]uint32
		enter, exit uint32
	}{
		{"read", [2]uint32{0, 63}, enterProgNoPayload, exitProgFDTime},
		{"write", [2]uint32{1, 64}, enterProgPayload, exitProgGeneric},
		{"close", [2]uint32{3, 57}, enterProgNoPayload, exitProgGeneric},
		{"openat", [2]uint32{257, 56}, enterProgPayload, exitProgPath},
		{"readlinkat", [2]uint32{267, 78}, enterProgReadlink, exitProgStruct},
		{"clone", [2]uint32{56, 220}, enterProgNoPayload, exitProgGeneric},
		{"clone3", [2]uint32{435, 435}, enterProgClone3, exitProgGeneric},
		{"execve", [2]uint32{59, 221}, enterProgExec, exitProgIO},
		{"execveat", [2]uint32{322, 281}, enterProgExec, exitProgIO},
		{"socket", [2]uint32{41, 198}, enterProgNoPayload, exitProgFDTime},
		{"connect", [2]uint32{42, 203}, enterProgNetwork, exitProgControl},
		{"accept", [2]uint32{43, 202}, enterProgNetwork, exitProgControl},
		{"dup", [2]uint32{32, 23}, enterProgNoPayload, exitProgFDTime},
		{"fcntl", [2]uint32{72, 25}, enterProgFcntl, exitProgControl},
		{"ioctl", [2]uint32{16, 29}, enterProgIoctl, exitProgControl},
		{"futex", [2]uint32{202, 98}, enterProgFutex, exitProgGeneric},
		{"epoll_pwait", [2]uint32{281, 22}, enterProgNoPayload, exitProgIO},
	} {
		id := tc.ids[index]
		if table[id].Name != tc.name || plan.enter[id] != tc.enter || plan.exit[id] != tc.exit {
			t.Errorf("%s id=%d: name=%s routes=(%d,%d), want %s (%d,%d)", target, id, table[id].Name, plan.enter[id], plan.exit[id], tc.name, tc.enter, tc.exit)
		}
	}
	if len(plan.enter) != len(table) || len(plan.exit) != len(table) {
		t.Fatal("route cardinality differs from target metadata")
	}
	for id := range plan.enter {
		if _, exists := table[id]; !exists {
			t.Fatalf("route for unavailable syscall %d", id)
		}
	}
}

func TestSpecializedRoutesHaveNativeMetadata(t *testing.T) {
	amd64 := architectureTableForTest(t, "amd64")
	arm64 := architectureTableForTest(t, "arm64")
	for name := range bpfRouteCapabilities {
		_, x86 := routeSyscallIDByName(amd64, name)
		_, arm := routeSyscallIDByName(arm64, name)
		if !x86 && !arm {
			t.Errorf("specialized syscall %s has no supported native ABI", name)
		}
	}
}
