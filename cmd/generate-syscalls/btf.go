package main

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// loadBTFSyscalls extracts syscall signatures from kernel BTF.
// It searches __do_sys_* and ksys_* functions, returning a map
// of syscall name → SyscallMeta with parameter names and types.
func loadBTFSyscalls() (map[string]SyscallMeta, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load kernel BTF: %w", err)
	}

	result := make(map[string]SyscallMeta)

	for typ, err := range spec.All() {
		if err != nil {
			return nil, fmt.Errorf("iterate BTF: %w", err)
		}
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		var syscallName string
		if strings.HasPrefix(fn.Name, "__do_sys_") {
			syscallName = strings.TrimPrefix(fn.Name, "__do_sys_")
		} else if strings.HasPrefix(fn.Name, "ksys_") {
			syscallName = strings.TrimPrefix(fn.Name, "ksys_")
		} else {
			continue
		}

		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok || len(proto.Params) == 0 {
			continue
		}

		// Skip functions with only pt_regs param (no real arg info)
		if len(proto.Params) == 1 && proto.Params[0].Name == "__unused" {
			continue
		}

		// Skip internal helpers (e.g. ksys_sync_helper)
		if strings.Contains(syscallName, "_helper") {
			continue
		}

		// __do_sys_ takes priority over ksys_
		if _, exists := result[syscallName]; exists && strings.HasPrefix(fn.Name, "ksys_") {
			continue
		}

		args := make([]string, 0, len(proto.Params))
		argTypes := make([]string, 0, len(proto.Params))
		for _, p := range proto.Params {
			args = append(args, p.Name)
			argTypes = append(argTypes, resolveType(p.Type))
		}

		result[syscallName] = SyscallMeta{
			Name:     syscallName,
			Args:     args,
			ArgTypes: argTypes,
		}
	}

	return result, nil
}

// resolveType converts a BTF type to a C-like type string.
func resolveType(t btf.Type) string {
	switch v := t.(type) {
	case *btf.Pointer:
		return resolveType(v.Target) + " *"
	case *btf.Const:
		return "const " + resolveType(v.Type)
	case *btf.Volatile:
		return "volatile " + resolveType(v.Type)
	case *btf.Restrict:
		return resolveType(v.Type)
	case *btf.Typedef:
		return v.Name
	case *btf.Int:
		return v.Name
	case *btf.Struct:
		if v.Name != "" {
			return "struct " + v.Name
		}
		return "struct (anon)"
	case *btf.Union:
		if v.Name != "" {
			return "union " + v.Name
		}
		return "union (anon)"
	case *btf.Enum:
		if v.Name != "" {
			return "enum " + v.Name
		}
		return "int"
	case *btf.Void:
		return "void"
	case *btf.Array:
		return resolveType(v.Type) + "[]"
	default:
		return fmt.Sprintf("%#x", 0)
	}
}
