package main

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"sort"
	"strace-go/internal/architecture"
	"strings"
)

// syscallNumberEntry is the kernel ABI identity used to join semantic metadata.
type syscallNumberEntry struct {
	ID   int
	Name string
}

type unixSyscallSource struct{ target architecture.Architecture }

func (source unixSyscallSource) LoadSyscallNumbers() ([]syscallNumberEntry, error) {
	target := source.target
	if target == "" {
		target = architecture.Architecture(runtime.GOARCH)
	}
	path, err := unixSysnumPathFor(target)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open x/sys syscall numbers %s: %w", path, err)
	}
	defer file.Close()

	constants, err := parseUnixSyscallConstants(file)
	if err != nil {
		return nil, fmt.Errorf("parse x/sys syscall numbers %s: %w", path, err)
	}
	entries := make([]syscallNumberEntry, 0, len(constants))
	for constantName, id := range constants {
		name := strings.ToLower(strings.TrimPrefix(constantName, "SYS_"))
		if name == "arch_specific_syscall" {
			continue
		}
		if name == "" {
			return nil, fmt.Errorf("invalid empty syscall name from constant %s", constantName)
		}
		entries = append(entries, syscallNumberEntry{ID: id, Name: name})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ID == entries[j].ID {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].ID < entries[j].ID
	})
	return entries, nil
}

func unixSysnumPathFor(target architecture.Architecture) (string, error) {
	if _, err := architecture.Parse(string(target)); err != nil {
		return "", err
	}
	output, err := exec.Command("go", "list", "-f", "{{.Dir}}", "golang.org/x/sys/unix").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("locate golang.org/x/sys/unix: %w: %s", err, strings.TrimSpace(string(output)))
	}
	directory := strings.TrimSpace(string(output))
	if directory == "" {
		return "", fmt.Errorf("locate golang.org/x/sys/unix: empty module directory")
	}
	return filepath.Join(directory, fmt.Sprintf("zsysnum_%s_%s.go", "linux", target)), nil
}

func parseUnixSyscallConstants(reader io.Reader) (map[string]int, error) {
	source, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "syscall_numbers.go", source, 0)
	if err != nil {
		return nil, fmt.Errorf("parse Go source: %w", err)
	}
	info := &types.Info{Defs: make(map[*ast.Ident]types.Object)}
	config := types.Config{Importer: importer.Default()}
	if _, err := config.Check("unix", fileSet, []*ast.File{file}, info); err != nil {
		return nil, fmt.Errorf("type-check Go source: %w", err)
	}

	constants := make(map[string]int)
	for identifier, object := range info.Defs {
		if identifier == nil || !strings.HasPrefix(identifier.Name, "SYS_") {
			continue
		}
		constantObject, ok := object.(*types.Const)
		if !ok {
			continue
		}
		value, ok := constant.Int64Val(constantObject.Val())
		if !ok || value < 0 || int64(int(value)) != value {
			return nil, fmt.Errorf("syscall constant %s is not a non-negative int", identifier.Name)
		}
		constants[identifier.Name] = int(value)
	}
	return constants, nil
}
