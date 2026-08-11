package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
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

func hasConcreteFieldPointer(file *ast.File, fieldName, typeName string) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		field, ok := node.(*ast.Field)
		if !ok {
			return true
		}
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			return true
		}
		name, ok := star.X.(*ast.Ident)
		if !ok || name.Name != typeName {
			return true
		}
		for _, fieldIdent := range field.Names {
			if fieldIdent.Name == fieldName {
				found = true
			}
		}
		return true
	})
	return found
}

func hasConcreteTraceStatePointer(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		star, ok := node.(*ast.StarExpr)
		if !ok {
			return true
		}
		name, ok := star.X.(*ast.Ident)
		if ok && name.Name == "TraceState" {
			found = true
		}
		return true
	})
	return found
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

func globalXlatPolicyViolations(path string, source []byte, forbidden map[string]bool) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		return nil, err
	}
	aliases, importViolations := metaImportAliases(path, file)
	violations := append([]string{}, importViolations...)
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || !forbidden[selector.Sel.Name] {
			return true
		}
		packageName, ok := selector.X.(*ast.Ident)
		if ok && aliases[packageName.Name] {
			violations = append(violations, fmt.Sprintf("%s references global %s.%s", path, packageName.Name, selector.Sel.Name))
		}
		return true
	})
	return violations, nil
}

func metaImportAliases(path string, file *ast.File) (map[string]bool, []string) {
	aliases := make(map[string]bool)
	var violations []string
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath != "strace-go/pkg/meta" {
			continue
		}
		if spec.Name == nil {
			aliases["meta"] = true
			continue
		}
		switch spec.Name.Name {
		case ".":
			violations = append(violations, policyViolation(path, "dot import strace-go/pkg/meta"))
		case "_":
		default:
			aliases[spec.Name.Name] = true
		}
	}
	return aliases, violations
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
		"pkg/meta/syscall_table.go",
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

func runtimeMemoryPolicyViolations(path string, source []byte) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		return nil, err
	}
	aliases, violations := runtimeImportAliases(path, file)
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.Ident:
			if isLegacyMemoryIdentifier(node.Name) {
				violations = append(violations, policyViolation(path, node.Name))
			}
		case *ast.SelectorExpr:
			pkg, ok := node.X.(*ast.Ident)
			if ok && isForbiddenRuntimeSelector(aliases[pkg.Name], node.Sel.Name) {
				violations = append(violations, policyViolation(path, pkg.Name+"."+node.Sel.Name))
			}
		}
		return true
	})
	return violations, nil
}

func runtimeImportAliases(path string, file *ast.File) (map[string]string, []string) {
	aliases := make(map[string]string)
	var violations []string
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if importPath == "strace-go/pkg/procmem" {
			violations = append(violations, policyViolation(path, importPath))
		}
		if !isRuntimeMemoryPackage(importPath) {
			continue
		}
		name := runtimeImportName(spec, importPath)
		if name == "." {
			violations = append(violations, policyViolation(path, "dot import "+importPath))
			continue
		}
		if name != "_" {
			aliases[name] = importPath
		}
	}
	return aliases, violations
}

func runtimeImportName(spec *ast.ImportSpec, importPath string) string {
	if spec.Name != nil {
		return spec.Name.Name
	}
	if importPath == "syscall" {
		return "syscall"
	}
	return "unix"
}

func isForbiddenRuntimeSelector(importPath string, selector string) bool {
	if !isRuntimeMemoryPackage(importPath) {
		return false
	}
	return strings.HasPrefix(selector, "Ptrace") ||
		selector == "ProcessVMReadv" ||
		selector == "SYS_PTRACE" ||
		isRawSyscallSelector(selector)
}

func isRuntimeMemoryPackage(importPath string) bool {
	return importPath == "golang.org/x/sys/unix" || importPath == "syscall"
}

func isRawSyscallSelector(selector string) bool {
	return selector == "Syscall" || selector == "Syscall6" ||
		selector == "RawSyscall" || selector == "RawSyscall6"
}

func isLegacyMemoryIdentifier(name string) bool {
	return name == "MemReader" || name == "MemoryReader" || name == "ReadRobust"
}

func policyViolation(path string, symbol string) string {
	return path + ": " + symbol
}

func productGoFiles(t *testing.T) []string {
	t.Helper()
	root := repositoryRoot(t)
	var files []string
	for _, dir := range []string{filepath.Join(root, "cmd/strace-go"), filepath.Join(root, "pkg")} {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(files)
	return files
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func procfsStringLiterals(t *testing.T, path string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var refs []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("unquote %s literal %q: %v", path, literal.Value, err)
		}
		if strings.Contains(value, "/proc/") {
			refs = append(refs, value)
		}
		return true
	})
	return refs
}
