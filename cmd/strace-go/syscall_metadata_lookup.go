package main

import "strace-go/pkg/meta"

const syscallMetadataTableSize = 512

// syscallMetadataTable is the immutable ID-indexed metadata snapshot for one session.
type syscallMetadataTable struct {
	entries [syscallMetadataTableSize]meta.Syscall
	present [syscallMetadataTableSize]bool
}

func newSyscallMetadataTable(source map[uint32]meta.Syscall) *syscallMetadataTable {
	table := &syscallMetadataTable{}
	for id, syscall := range source {
		if id >= uint32(len(table.entries)) {
			continue
		}
		table.entries[id] = syscall
		table.present[id] = true
	}
	return table
}

func (table *syscallMetadataTable) lookup(id uint32) (meta.Syscall, bool) {
	if table == nil || id >= uint32(len(table.entries)) || !table.present[id] {
		return meta.Syscall{}, false
	}
	return table.entries[id], true
}

func lookupSyscallMetadata(table *syscallMetadataTable, id uint32) meta.Syscall {
	if syscall, ok := table.lookup(id); ok {
		return syscall
	}
	return syscallMeta(id)
}
