package main

import (
	"fmt"

	"strace-go/internal/architecture"
)

// syscallSignature is the reviewed formatter-facing native LP64 argument schema.
type syscallSignature struct {
	Args     []string
	ArgTypes []string
}

func loadTargetSyscalls(target architecture.Architecture) (map[int]SyscallMeta, error) {
	numbers, err := (unixSyscallSource{target: target}).LoadSyscallNumbers()
	if err != nil {
		return nil, err
	}
	semantic, err := (checkedInSyscallSemanticSource{}).LoadSyscallEntries()
	if err != nil {
		return nil, err
	}
	entries, err := mergeSyscallEntries(numbers, semantic)
	if err != nil {
		return nil, err
	}
	table := make(map[int]SyscallMeta, len(entries))
	for _, entry := range entries {
		signature, err := targetSignature(target, entry)
		if err != nil {
			return nil, err
		}
		table[entry.ID] = SyscallMeta{Name: entry.Name, Args: signature.Args, ArgTypes: signature.ArgTypes, Flags: entry.Flags}
	}
	return table, nil
}

func targetSignature(target architecture.Architecture, entry syscallentEntry) (syscallSignature, error) {
	signature, ok := nativeSyscallSignatures[entry.Name]
	if !ok || len(signature.Args) != entry.Argc || len(signature.ArgTypes) != entry.Argc || entry.Argc > 6 {
		return syscallSignature{}, fmt.Errorf("invalid native signature for %s/%s", target, entry.Name)
	}
	signature.Args = append([]string{}, signature.Args...)
	signature.ArgTypes = append([]string{}, signature.ArgTypes...)
	if target == architecture.ARM64 && entry.Name == "clone" {
		signature.Args[3], signature.Args[4] = signature.Args[4], signature.Args[3]
		signature.ArgTypes[3], signature.ArgTypes[4] = signature.ArgTypes[4], signature.ArgTypes[3]
	}
	return signature, nil
}
