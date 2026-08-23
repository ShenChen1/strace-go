package main

import "strace-go/pkg/meta"

const syscallMetadataTableSize = 512

// syscallMetadataTable is the immutable ID-indexed metadata snapshot for one session.
type syscallMetadataTable struct {
	entries [syscallMetadataTableSize]meta.Syscall
	present [syscallMetadataTableSize]bool
	traits  [syscallMetadataTableSize]syscallEventTraits
}

func newSyscallMetadataTable(source map[uint32]meta.Syscall) *syscallMetadataTable {
	table := &syscallMetadataTable{}
	for id, syscall := range source {
		if id >= uint32(len(table.entries)) {
			continue
		}
		table.entries[id] = syscall
		table.present[id] = true
		table.traits[id] = syscallEventTraitsForName(syscall.Name)
	}
	return table
}

func (table *syscallMetadataTable) lookup(id uint32) (meta.Syscall, bool) {
	if table == nil || id >= uint32(len(table.entries)) || !table.present[id] {
		return meta.Syscall{}, false
	}
	return table.entries[id], true
}

func lookupSyscallMetadataWithTraits(
	table *syscallMetadataTable,
	view syscallEventView,
) (meta.Syscall, syscallEventTraits, bool) {
	if table != nil && view.sysID < uint32(len(table.entries)) && table.present[view.sysID] {
		return table.entries[view.sysID], table.traits[view.sysID], true
	}
	scMeta := syscallMeta(view.sysID)
	return scMeta, syscallEventTraitsForView(view, scMeta.Name), false
}

func lookupSyscallMetadata(table *syscallMetadataTable, id uint32) meta.Syscall {
	if syscall, ok := table.lookup(id); ok {
		return syscall
	}
	return syscallMeta(id)
}
