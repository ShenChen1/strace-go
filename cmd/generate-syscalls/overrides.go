package main

// BTF uses different function names for some syscalls.
// This maps a BTF name to the canonical syscall name used by the catalog.
var btfNameToCanonicalSyscall = map[string]string{
	"newstat":    "stat",
	"newlstat":   "lstat",
	"newfstat":   "fstat",
	"newuname":   "uname",
	"mmap_pgoff": "mmap",
	"sendfile64": "sendfile",
	"umount":     "umount2",
}

func allSyscallOverrides() map[string]SyscallMeta {
	result := make(map[string]SyscallMeta, len(semanticOverrides))
	for name, meta := range semanticOverrides {
		result[name] = meta
	}
	return result
}
