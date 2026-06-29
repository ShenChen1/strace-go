package main

import (
	"fmt"
	"log"
	"sort"
)

type SyscallMeta struct {
	Name     string
	Args     []string
	ArgTypes []string
	Flags    string
}

func main() {
	if err := loadCapturePolicy("capture_rules.yaml"); err != nil {
		log.Fatalf("failed to load capture policy: %v", err)
	}

	syscalls, err := LoadSyscalls()
	if err != nil {
		log.Fatalf("failed to load syscalls: %v", err)
	}

	if err := writeBPFCaptureHeader("../../bpf/syscall_capture.h", syscalls); err != nil {
		log.Fatalf("failed to write syscall_capture.h: %v", err)
	}
	if err := writeGoSyscallTable("../../pkg/meta/syscall_table.go", syscalls); err != nil {
		log.Fatalf("failed to write syscall_table.go: %v", err)
	}
}

func sortedKeys(m map[int]SyscallMeta) []int {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func LoadSyscalls() (map[int]SyscallMeta, error) {
	btf, err := loadBTFSyscalls()
	if err != nil {
		return nil, err
	}

	entries, err := parseSyscallent("../../strace-upstream/src/linux/x86_64/syscallent.h")
	if err != nil {
		return nil, err
	}

	res := make(map[int]SyscallMeta)
	for _, ent := range entries {
		// Priority 1: manual overrides
		if m, ok := manualOverrides[ent.Name]; ok {
			m.Flags = ent.Flags
			res[ent.ID] = m
			continue
		}
		// Priority 2: BTF
		if meta, ok := btf[ent.Name]; ok {
			meta.Flags = ent.Flags
			res[ent.ID] = meta
			continue
		}
		// Priority 3: btfNameToSyscallent mapping
		found := false
		for btfName, sentName := range btfNameToSyscallent {
			if sentName == ent.Name {
				if meta, ok := btf[btfName]; ok {
					meta.Name = sentName
					meta.Flags = ent.Flags
					res[ent.ID] = meta
					found = true
					break
				}
			}
		}
		if found {
			continue
		}

		// Fallback: dummy
		dummyArgs := make([]string, ent.Argc)
		dummyTypes := make([]string, ent.Argc)
		for i := 0; i < ent.Argc; i++ {
			dummyArgs[i] = fmt.Sprintf("arg%d", i)
			dummyTypes[i] = "unsigned long"
		}
		res[ent.ID] = SyscallMeta{Name: ent.Name, Args: dummyArgs, ArgTypes: dummyTypes, Flags: ent.Flags}
	}
	return res, nil
}
