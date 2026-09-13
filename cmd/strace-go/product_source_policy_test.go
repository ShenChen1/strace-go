package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductSourceHasNoRuntimePtraceOrProcmemDependency(t *testing.T) {
	for _, path := range productGoFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		violations, err := runtimeMemoryPolicyViolations(path, source)
		if err != nil {
			t.Fatalf("inspect %s: %v", path, err)
		}
		if len(violations) != 0 {
			t.Fatalf("forbidden runtime memory dependency:\n%s", strings.Join(violations, "\n"))
		}
	}
}

func TestProductSourceHasNoGlobalXlatState(t *testing.T) {
	forbidden := map[string]bool{
		"XlatFormat":        true,
		"XlatTables":        true,
		"SyscallArgXlatMap": true,
	}
	for _, path := range productGoFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		violations, err := globalXlatPolicyViolations(path, source, forbidden)
		if err != nil {
			t.Fatalf("inspect %s: %v", path, err)
		}
		for _, violation := range violations {
			t.Error(violation)
		}
	}
}

func TestProductSourceKeepsFDStateBehindReaderPorts(t *testing.T) {
	forbidden := []string{
		"FdMap:",
		"FDStates:",
		"EventFDPaths:",
		"EventFDStates:",
		"EventCwdPath:",
		"PathMap()",
		"FDStateMap()",
		"FDCloexecMap()",
	}
	for _, path := range productGoFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, token := range forbidden {
			if strings.Contains(string(source), token) {
				t.Fatalf("%s contains forbidden mutable FD-state boundary %q", path, token)
			}
		}
	}
}

func TestProductOutputComponentsKeepTraceStateBehindPorts(t *testing.T) {
	for _, relative := range []string{
		"cmd/strace-go/event_router.go",
		"cmd/strace-go/text_renderer.go",
		"cmd/strace-go/exec_syscall_output.go",
		"cmd/strace-go/suspended_syscall_output.go",
	} {
		path := filepath.Join(repositoryRoot(t), relative)
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if hasConcreteTraceStatePointer(file) {
			t.Fatalf("%s directly depends on concrete TraceState", relative)
		}
	}
}

func TestProductEventContextKeepsFDStateBehindReaderPorts(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "cmd/strace-go/syscall_event_context.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if hasConcreteFieldPointer(file, "fdState", "FDStateStore") {
		t.Fatal("syscallEventContextDeps directly depends on concrete FDStateStore")
	}
}

func TestGlobalXlatPolicyDetectsAliasedMetaImport(t *testing.T) {
	forbidden := map[string]bool{
		"XlatFormat":        true,
		"XlatTables":        true,
		"SyscallArgXlatMap": true,
	}
	source := []byte(`package fixture
import m "strace-go/pkg/meta"
var _ = m.XlatFormat
`)
	violations, err := globalXlatPolicyViolations("fixture.go", source, forbidden)
	if err != nil {
		t.Fatalf("globalXlatPolicyViolations: %v", err)
	}
	if len(violations) != 1 || !strings.Contains(violations[0], "m.XlatFormat") {
		t.Fatalf("violations = %q, want aliased global reference", violations)
	}
}

func TestRuntimeMemoryPolicyDetectsForbiddenSource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name: "metadata syscall is allowed",
			source: `package fixture
import linux "golang.org/x/sys/unix"
func readClock(ts *linux.Timespec) { _ = linux.ClockGettime(linux.CLOCK_MONOTONIC, ts) }
`,
		},
		{
			name: "aliased ptrace call",
			source: `package fixture
import linux "golang.org/x/sys/unix"
func readMemory() { _, _ = linux.PtracePeekData(1, 2, nil) }
`,
			want: "PtracePeekData",
		},
		{
			name: "raw syscall bypass",
			source: `package fixture
import linux "golang.org/x/sys/unix"
func readMemory() { _, _, _ = linux.Syscall6(101, 0, 0, 0, 0, 0, 0) }
`,
			want: "linux.Syscall6",
		},
		{
			name: "process vm read",
			source: `package fixture
import linux "golang.org/x/sys/unix"
func readMemory() { _, _ = linux.ProcessVMReadv(1, nil, nil, 0) }
`,
			want: "ProcessVMReadv",
		},
		{
			name: "procmem import",
			source: `package fixture
import memory "strace-go/pkg/procmem"
var _ = memory.NewReader
`,
			want: "strace-go/pkg/procmem",
		},
		{
			name:   "legacy memory reader",
			source: "package fixture\ntype MemReader interface { ReadRobust() }\n",
			want:   "MemReader",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			violations, err := runtimeMemoryPolicyViolations("fixture.go", []byte(test.source))
			if err != nil {
				t.Fatalf("runtimeMemoryPolicyViolations: %v", err)
			}
			joined := strings.Join(violations, "\n")
			if test.want == "" && joined != "" {
				t.Fatalf("allowed source violations: %s", joined)
			}
			if test.want != "" && !strings.Contains(joined, test.want) {
				t.Fatalf("violations = %q, want token %q", joined, test.want)
			}
		})
	}
}

func TestProductGoFilesCoverRuntimeTree(t *testing.T) {
	root := repositoryRoot(t)
	found := make(map[string]bool)
	for _, path := range productGoFiles(t) {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatalf("relative path for %s: %v", path, err)
		}
		found[filepath.ToSlash(relative)] = true
	}
	for _, expected := range []string{
		"cmd/strace-go/main.go",
		"pkg/handler/handler.go",
		"pkg/meta/syscall_table_amd64.go",
		"pkg/meta/syscall_table_arm64.go",
		"pkg/stacktrace/resolver.go",
	} {
		if !found[expected] {
			t.Errorf("product source discovery missed %s", expected)
		}
	}
}

func TestProductSourceHasNoProcfsDependency(t *testing.T) {
	for _, path := range productGoFiles(t) {
		for _, ref := range procfsStringLiterals(t, path) {
			t.Fatalf("%s contains procfs reference %q", path, ref)
		}
	}
}

func TestProductSourceHasNoEventTimeProcfsDependency(t *testing.T) {
	forbidden := []string{
		"/proc/%d/fd",
		"/proc/%d/cwd",
		"/proc/%d/fdinfo",
		"/proc/net/",
	}
	for _, path := range productGoFiles(t) {
		for _, ref := range procfsStringLiterals(t, path) {
			for _, token := range forbidden {
				if strings.Contains(ref, token) {
					t.Fatalf("%s contains event-time procfs reference %q", path, ref)
				}
			}
		}
	}
}

func TestProductSourceHasNoFixedWindowPayloadProjection(t *testing.T) {
	forbidden := []string{
		"payloadSectionsForPayloadEvent",
		"payloadSourceSectionRules",
		"type payloadEvent",
		"type payloadEventMeta",
		"type payloadSource interface",
		"type windowPayloadSource",
		"type sectionPayloadSource",
		"type payloadWindowSpec",
		"newWindowPayloadEventFromRaw",
		"newWindowPayloadSourceFromRaw",
		"payloadEnterArgOffset",
		"payloadMiscArgOffset",
		"payloadExitArgOffset",
		"PayloadWindow(",
	}
	for _, path := range productGoFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, forbiddenToken := range forbidden {
			if strings.Contains(string(source), forbiddenToken) {
				t.Fatalf("%s contains forbidden fixed-window token %q", path, forbiddenToken)
			}
		}
	}
}
