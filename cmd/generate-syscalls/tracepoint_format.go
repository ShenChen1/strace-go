package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	tracepointFormatRoot      = "/sys/kernel/tracing/events/syscalls"
	debugTracepointFormatRoot = "/sys/kernel/debug/tracing/events/syscalls"
)

type tracepointSyscallSource interface {
	LoadTracepointSyscalls(names []string) (map[string]SyscallMeta, error)
}

type tracepointFormatFileSystem interface {
	ReadFile(path string) ([]byte, error)
}

type tracepointFormatRootChecker interface {
	CheckTracepointRoot(path string) error
}

type osTracepointFormatFileSystem struct{}

func (osTracepointFormatFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (osTracepointFormatFileSystem) CheckTracepointRoot(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func tracepointLookupNames(names []string, aliases map[string]string) []string {
	seen := make(map[string]struct{}, len(names)+len(aliases))
	for _, name := range names {
		seen[name] = struct{}{}
	}
	for alias, syscallentName := range aliases {
		if _, ok := seen[syscallentName]; ok {
			seen[alias] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func tracepointAliasNames(name string, aliases map[string]string) []string {
	result := make([]string, 0)
	for alias, syscallentName := range aliases {
		if syscallentName == name {
			result = append(result, alias)
		}
	}
	sort.Strings(result)
	return result
}

type kernelTracepointFormatSource struct {
	fs    tracepointFormatFileSystem
	roots []string
}

func (s kernelTracepointFormatSource) LoadTracepointSyscalls(names []string) (map[string]SyscallMeta, error) {
	reader := s.fs
	if reader == nil {
		reader = osTracepointFormatFileSystem{}
	}
	roots := s.roots
	if len(roots) == 0 {
		roots = []string{tracepointFormatRoot, debugTracepointFormatRoot}
	}
	if checker, ok := reader.(tracepointFormatRootChecker); ok {
		if err := ensureTracepointRoot(checker, roots); err != nil {
			return nil, err
		}
	}

	result := make(map[string]SyscallMeta)
	for _, name := range names {
		if !validTracepointSyscallName(name) {
			return nil, fmt.Errorf("invalid syscall name %q", name)
		}
		meta, ok, err := readTracepointSyscall(reader, roots, name)
		if err != nil {
			return nil, err
		}
		if ok {
			result[name] = meta
		}
	}
	return result, nil
}

func ensureTracepointRoot(checker tracepointFormatRootChecker, roots []string) error {
	failures := make([]string, 0, len(roots))
	for _, root := range roots {
		if err := checker.CheckTracepointRoot(root); err == nil {
			return nil
		} else {
			failures = append(failures, fmt.Sprintf("%s: %v", root, err))
		}
	}
	return fmt.Errorf("no readable syscall tracepoint root: %s", strings.Join(failures, "; "))
}

func readTracepointSyscall(reader tracepointFormatFileSystem, roots []string, name string) (SyscallMeta, bool, error) {
	var permissionErr error
	for _, root := range roots {
		path := filepath.Join(root, "sys_enter_"+name, "format")
		data, err := reader.ReadFile(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if errors.Is(err, fs.ErrPermission) {
				permissionErr = err
				continue
			}
			return SyscallMeta{}, false, fmt.Errorf("read syscall tracepoint %s: %w", name, err)
		}
		meta, err := parseTracepointFormat(name, bytes.NewReader(data))
		if err != nil {
			return SyscallMeta{}, false, fmt.Errorf("parse syscall tracepoint %s: %w", name, err)
		}
		return meta, true, nil
	}
	if permissionErr != nil {
		return SyscallMeta{}, false, fmt.Errorf("read syscall tracepoint %s: %w", name, permissionErr)
	}
	return SyscallMeta{}, false, nil
}

func parseTracepointFormat(name string, input io.Reader) (SyscallMeta, error) {
	scanner := bufio.NewScanner(input)
	args := make([]string, 0, 6)
	argTypes := make([]string, 0, 6)
	sawField := false
	for scanner.Scan() {
		declaration, ok := tracepointFieldDeclaration(scanner.Text())
		if !ok {
			continue
		}
		sawField = true
		if isTracepointMetadataField(declaration) {
			continue
		}
		argName, argType, ok := splitTracepointField(declaration)
		if !ok {
			return SyscallMeta{}, fmt.Errorf("invalid field declaration %q", declaration)
		}
		args = append(args, argName)
		argTypes = append(argTypes, argType)
	}
	if err := scanner.Err(); err != nil {
		return SyscallMeta{}, fmt.Errorf("scan format: %w", err)
	}
	if !sawField {
		return SyscallMeta{}, errors.New("no syscall argument fields")
	}
	return SyscallMeta{Name: name, Args: args, ArgTypes: argTypes}, nil
}

func tracepointFieldDeclaration(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "field:") {
		return "", false
	}
	declaration := strings.TrimSpace(strings.TrimPrefix(line, "field:"))
	end := strings.IndexByte(declaration, ';')
	if end < 0 {
		return "", false
	}
	declaration = strings.TrimSpace(declaration[:end])
	return declaration, declaration != ""
}

func isTracepointMetadataField(declaration string) bool {
	if strings.HasPrefix(declaration, "common_") || strings.HasPrefix(declaration, "__data_loc ") {
		return true
	}
	fields := strings.Fields(declaration)
	if len(fields) == 0 {
		return true
	}
	name := fields[len(fields)-1]
	return strings.HasPrefix(name, "common_") || name == "ent" || name == "__syscall_nr" || name == "id" || name == "args" || name == "__data"
}

func splitTracepointField(declaration string) (string, string, bool) {
	fields := strings.Fields(declaration)
	if len(fields) < 2 {
		return "", "", false
	}
	rawName := fields[len(fields)-1]
	if strings.ContainsAny(rawName, "[]") {
		return "", "", false
	}
	name := strings.TrimLeft(rawName, "*")
	if name == "" {
		return "", "", false
	}
	argType := strings.TrimSpace(strings.TrimSuffix(declaration, rawName))
	if pointerDepth := len(rawName) - len(name); pointerDepth > 0 {
		argType += strings.Repeat(" *", pointerDepth)
	}
	if argType == "" {
		return "", "", false
	}
	return name, argType, true
}

func validTracepointSyscallName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		char := name[i]
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' {
			continue
		}
		return false
	}
	return true
}
