package main

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// loadBTFSyscalls extracts syscall signatures from kernel BTF.
func loadBTFSyscalls() (map[string]SyscallMeta, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load kernel BTF: %w", err)
	}

	result := make(map[string]SyscallMeta)
	// Keep track of the source function name to handle priorities
	sources := make(map[string]string)

	for typ, err := range spec.All() {
		if err != nil {
			return nil, fmt.Errorf("iterate BTF: %w", err)
		}
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		var syscallName string
		if strings.HasPrefix(fn.Name, "__x64_sys_") {
			syscallName = strings.TrimPrefix(fn.Name, "__x64_sys_")
		} else if strings.HasPrefix(fn.Name, "__do_sys_") {
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

		// Skip functions with only pt_regs or __unused param
		if len(proto.Params) == 1 && (proto.Params[0].Name == "regs" || proto.Params[0].Name == "__unused" || proto.Params[0].Name == "unused") {
			continue
		}

		// Skip internal helpers
		if strings.Contains(syscallName, "_helper") {
			continue
		}

		// __do_sys_ usually has the best info, then __x64_sys_, then ksys_
		// Actually, let's just pick the one with the most parameters if names are the same
		if oldMeta, exists := result[syscallName]; exists {
			if len(proto.Params) < len(oldMeta.Args) {
				continue
			}
			// If same number of params, prioritize __do_sys_ over others
			if len(proto.Params) == len(oldMeta.Args) {
				if !strings.HasPrefix(fn.Name, "__do_sys_") {
					continue
				}
			}
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
		sources[syscallName] = fn.Name
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
		return "unsigned long"
	}
}
