package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestIsPassThroughFDTarget(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{target: "/tmp/output", want: true},
		{target: "/dev/full", want: true},
		{target: "/proc/123/fd/4", want: false},
		{target: "/sys/kernel/debug", want: false},
		{target: "pipe:[123]", want: false},
		{target: "socket:[123]", want: false},
		{target: "anon_inode:bpf-link", want: false},
		{target: "relative/path", want: false},
	}

	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			if got := isPassThroughFDTarget(test.target); got != test.want {
				t.Fatalf("isPassThroughFDTarget(%q) = %v, want %v", test.target, got, test.want)
			}
		})
	}
}

func TestNewTraceCommandDoesNotConfigurePtrace(t *testing.T) {
	cmd := newTraceCommand(&cli.Options{CmdArgs: []string{"/bin/true"}}, nil)
	if cmd.SysProcAttr != nil {
		t.Fatalf("SysProcAttr = %#v, want nil so tracing stays eBPF-only", cmd.SysProcAttr)
	}
}

func TestProductSourceHasNoRuntimePtraceOrProcmemDependency(t *testing.T) {
	forbidden := []string{
		"syscall.Ptrace",
		"unix.Ptrace",
		"PtracePeek",
		"PtraceAttach",
		"PtraceCont",
		"PtraceSetOptions",
		"PtraceSyscall",
		"ProcessVMReadv",
		"process_vm_readv(",
		"MemReader",
		"ReadRobust(",
		"\"strace-go/pkg/procmem\"",
		"procmem.",
		"/proc/%d/mem",
	}
	for _, path := range productGoFiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(data)
		for _, token := range forbidden {
			if strings.Contains(src, token) {
				t.Fatalf("%s contains forbidden runtime memory dependency token %q", path, token)
			}
		}
	}
}

func TestProductProcfsReferencesStayMetadataOnly(t *testing.T) {
	allowed := map[string]bool{
		"/proc/":             true,
		"/proc/%d/cwd":       true,
		"/proc/%d/fd":        true,
		"/proc/%d/fd/%d":     true,
		"/proc/%d/fd/%s":     true,
		"/proc/%d/fdinfo/%d": true,
		"/proc/%d/maps":      true,
		"/proc/net/tcp":      true,
		"/proc/net/tcp6":     true,
		"/proc/net/udp":      true,
		"/proc/net/udp6":     true,
		"/proc/net/unix":     true,
		"/proc/self/fd":      true,
		"/proc/self/fd/%d":   true,
	}
	for _, path := range productGoFiles(t) {
		for _, ref := range procfsStringLiterals(t, path) {
			if !allowed[ref] {
				t.Fatalf("%s contains non-metadata procfs reference %q", path, ref)
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
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(data)
		for _, token := range forbidden {
			if strings.Contains(src, token) {
				t.Fatalf("%s contains forbidden fixed-window payload projection token %q", path, token)
			}
		}
	}
}

func TestPendingSyscallsMapUsesCompactValue(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf() failed: %v", err)
	}

	if _, ok := spec.Maps["events_map"]; ok {
		t.Fatal("events_map should not remain as the syscall pending state map")
	}
	pending := spec.Maps["pending_syscalls"]
	if pending == nil {
		t.Fatal("pending_syscalls map missing from BPF object")
	}
	if pending.ValueSize > 128 {
		t.Fatalf("pending_syscalls value size = %d, want <= 128 bytes", pending.ValueSize)
	}
}

func TestShouldQueueExitStatusSkipsExplicitAttachPid(t *testing.T) {
	session := &traceSession{
		cmd:  fakeStartedCommand(),
		opts: &cli.Options{AttachPids: []int{202}},
	}
	coordinator := session.exitStatusCoordinator()

	if coordinator.ShouldQueue(202) {
		t.Fatal("explicit attach pid exit status should not wait for command exit")
	}
	if !coordinator.ShouldQueue(303) {
		t.Fatal("non-attached command tracee exit status should wait for command exit")
	}
}

func fakeStartedCommand() *exec.Cmd {
	return &exec.Cmd{}
}

func productGoFiles(t *testing.T) []string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	dirs := []string{
		filepath.Join(root, "cmd/strace-go"),
		filepath.Join(root, "pkg/cli"),
		filepath.Join(root, "pkg/event"),
		filepath.Join(root, "pkg/format"),
		filepath.Join(root, "pkg/handler"),
		filepath.Join(root, "pkg/stacktrace"),
	}
	var files []string
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") ||
				strings.HasSuffix(name, "_test.go") ||
				strings.HasPrefix(name, "bpf_bpf") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return files
}

func procfsStringLiterals(t *testing.T, path string) []string {
	t.Helper()
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var refs []string
	ast.Inspect(file, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("unquote %s literal %q: %v", path, lit.Value, err)
		}
		if strings.Contains(value, "/proc/") {
			refs = append(refs, value)
		}
		return true
	})
	return refs
}
