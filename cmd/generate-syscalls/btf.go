package main

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// loadBTFSyscalls extracts syscall signatures from kernel BTF.
func loadBTFSyscalls() (map[string]SyscallMeta, error) {
	types, err := loadKernelBTFTypes()
	if err != nil {
		return nil, err
	}
	return collectBTFSyscalls(types), nil
}

func loadBTFSyscallDiagnostics() (map[string]btfSyscallDiagnostic, error) {
	dataset, err := loadBTFSyscallDataset()
	if err != nil {
		return nil, err
	}
	return dataset.Diagnostics, nil
}

func loadBTFSyscallDataset() (btfSyscallDataset, error) {
	types, err := loadKernelBTFTypes()
	if err != nil {
		return btfSyscallDataset{}, err
	}
	return collectBTFSyscallDataset(types), nil
}

func loadKernelBTFTypes() ([]btf.Type, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load kernel BTF: %w", err)
	}

	var types []btf.Type
	for typ, err := range spec.All() {
		if err != nil {
			return nil, fmt.Errorf("iterate BTF: %w", err)
		}
		types = append(types, typ)
	}
	return types, nil
}

type btfSyscallDataset struct {
	Syscalls    map[string]SyscallMeta
	Diagnostics map[string]btfSyscallDiagnostic
}

func collectBTFSyscallDataset(types []btf.Type) btfSyscallDataset {
	syscalls := collectBTFSyscalls(types)
	return btfSyscallDataset{
		Syscalls:    syscalls,
		Diagnostics: collectBTFSyscallDiagnostics(types, syscalls),
	}
}

func collectBTFSyscalls(types []btf.Type) map[string]SyscallMeta {
	result := make(map[string]SyscallMeta)
	tracepointNames := make(map[string]bool)
	for _, typ := range types {
		st, ok := typ.(*btf.Struct)
		if !ok {
			continue
		}
		meta, ok := syscallMetaFromTracepointStruct(st)
		if !ok {
			continue
		}
		result[meta.Name] = meta
		tracepointNames[meta.Name] = true
	}

	for _, typ := range types {
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		syscallName, ok := syscallNameFromBTFFunc(fn.Name)
		if !ok {
			continue
		}
		if tracepointNames[syscallName] {
			continue
		}

		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok || len(proto.Params) == 0 {
			continue
		}

		if hasOnlyWrapperParam(proto.Params) {
			continue
		}

		// Skip internal helpers
		if strings.Contains(syscallName, "_helper") {
			continue
		}

		if oldMeta, exists := result[syscallName]; exists && !shouldUseBTFCandidate(oldMeta, fn.Name, len(proto.Params)) {
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

	return result
}

type btfSyscallDiagnostic struct {
	Function string
	Reason   string
}

const btfDiagnosticPTRegsWrapperOnly = "pt_regs_wrapper_only"

func collectBTFSyscallDiagnostics(types []btf.Type, usable map[string]SyscallMeta) map[string]btfSyscallDiagnostic {
	diagnostics := make(map[string]btfSyscallDiagnostic)
	for _, typ := range types {
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}
		syscallName, ok := syscallNameFromBTFFunc(fn.Name)
		if !ok {
			continue
		}
		if _, ok := usable[syscallName]; ok {
			continue
		}
		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok || !hasOnlyWrapperParam(proto.Params) {
			continue
		}
		diagnostics[syscallName] = btfSyscallDiagnostic{
			Function: fn.Name,
			Reason:   btfDiagnosticPTRegsWrapperOnly,
		}
	}
	return diagnostics
}

func hasOnlyWrapperParam(params []btf.FuncParam) bool {
	if len(params) != 1 {
		return false
	}
	switch params[0].Name {
	case "regs", "__unused", "unused":
		return true
	default:
		return false
	}
}

func syscallMetaFromTracepointStruct(st *btf.Struct) (SyscallMeta, bool) {
	name, ok := syscallNameFromTracepointStruct(st.Name)
	if !ok {
		return SyscallMeta{}, false
	}
	args := make([]string, 0, len(st.Members))
	argTypes := make([]string, 0, len(st.Members))
	for _, member := range st.Members {
		if isTracepointHeaderMember(member.Name) {
			continue
		}
		args = append(args, member.Name)
		argTypes = append(argTypes, resolveType(member.Type))
	}
	if len(args) == 0 {
		return SyscallMeta{}, false
	}
	return SyscallMeta{Name: name, Args: args, ArgTypes: argTypes}, true
}

func syscallNameFromTracepointStruct(name string) (string, bool) {
	const prefix = "trace_event_raw_sys_enter_"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	syscallName := strings.TrimPrefix(name, prefix)
	return syscallName, syscallName != ""
}

func isTracepointHeaderMember(name string) bool {
	switch {
	case name == "ent", name == "__syscall_nr", name == "__data":
		return true
	case strings.HasPrefix(name, "common_"):
		return true
	default:
		return false
	}
}

func syscallNameFromBTFFunc(name string) (string, bool) {
	switch {
	case strings.HasPrefix(name, "__x64_sys_"):
		return strings.TrimPrefix(name, "__x64_sys_"), true
	case strings.HasPrefix(name, "__arm64_sys_"):
		return strings.TrimPrefix(name, "__arm64_sys_"), true
	case strings.HasPrefix(name, "__do_sys_"):
		return strings.TrimPrefix(name, "__do_sys_"), true
	case strings.HasPrefix(name, "__sys_"):
		syscallName := strings.TrimPrefix(name, "__sys_")
		if internalSyscallBTFFuncs[syscallName] {
			return syscallName, true
		}
		return "", false
	case strings.HasPrefix(name, "ksys_"):
		return strings.TrimPrefix(name, "ksys_"), true
	default:
		return "", false
	}
}

var internalSyscallBTFFuncs = map[string]bool{
	"accept4":     true,
	"bind":        true,
	"bpf":         true,
	"connect":     true,
	"getsockname": true,
	"getsockopt":  true,
	"listen":      true,
	"recvfrom":    true,
	"recvmsg":     true,
	"sendmsg":     true,
	"sendto":      true,
	"setsockopt":  true,
	"shutdown":    true,
	"socket":      true,
	"socketpair":  true,
}

func shouldUseBTFCandidate(existing SyscallMeta, candidateFunc string, candidateArgc int) bool {
	if candidateArgc < len(existing.Args) {
		return false
	}
	if candidateArgc == len(existing.Args) {
		return strings.HasPrefix(candidateFunc, "__do_sys_")
	}
	return true
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
