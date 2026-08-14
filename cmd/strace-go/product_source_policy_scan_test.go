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
