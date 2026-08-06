package main

import "fmt"

type btfSyscallSource interface {
	LoadBTFSyscalls() (map[string]SyscallMeta, error)
}

type btfSyscallDiagnosticsSource interface {
	LoadBTFSyscallDiagnostics() (map[string]btfSyscallDiagnostic, error)
}

type btfSyscallDatasetSource interface {
	LoadBTFSyscallDataset() (btfSyscallDataset, error)
}

type syscallEntrySource interface {
	LoadSyscallEntries() ([]syscallentEntry, error)
}

type kernelBTFSource struct{}

func (kernelBTFSource) LoadBTFSyscalls() (map[string]SyscallMeta, error) {
	return loadBTFSyscalls()
}

func (kernelBTFSource) LoadBTFSyscallDiagnostics() (map[string]btfSyscallDiagnostic, error) {
	return loadBTFSyscallDiagnostics()
}

func (kernelBTFSource) LoadBTFSyscallDataset() (btfSyscallDataset, error) {
	return loadBTFSyscallDataset()
}

type defaultSyscallMetadataLoader struct{}

func (defaultSyscallMetadataLoader) Load() (map[int]SyscallMeta, error) {
	return LoadSyscalls()
}

type syscallentFileSource string

func (s syscallentFileSource) LoadSyscallEntries() ([]syscallentEntry, error) {
	return parseSyscallent(string(s))
}

type syscallMetadataLoader struct {
	btfSource   btfSyscallSource
	entrySource syscallEntrySource
	overrides   map[string]SyscallMeta
	aliases     map[string]string
}

func LoadSyscalls() (map[int]SyscallMeta, error) {
	loader, err := newDefaultSyscallMetadataLoader()
	if err != nil {
		return nil, err
	}
	return loader.Load()
}

func newDefaultSyscallMetadataLoader() (syscallMetadataLoader, error) {
	syscallentPath, err := resolveRepoPath(defaultSyscallentRelPath)
	if err != nil {
		return syscallMetadataLoader{}, err
	}
	loader := syscallMetadataLoader{
		btfSource:   kernelBTFSource{},
		entrySource: syscallentFileSource(syscallentPath),
		overrides:   manualOverrides,
		aliases:     btfNameToSyscallent,
	}
	return loader, nil
}

func (l syscallMetadataLoader) Load() (map[int]SyscallMeta, error) {
	btf, err := l.btfSource.LoadBTFSyscalls()
	if err != nil {
		return nil, err
	}
	entries, err := l.entrySource.LoadSyscallEntries()
	if err != nil {
		return nil, err
	}
	res := make(map[int]SyscallMeta, len(entries))
	for _, ent := range entries {
		res[ent.ID] = l.metaForEntry(ent, btf)
	}
	return res, nil
}

func (l syscallMetadataLoader) metaForEntry(ent syscallentEntry, btf map[string]SyscallMeta) SyscallMeta {
	if meta, ok := l.overrides[ent.Name]; ok {
		return withFlags(meta, ent.Flags)
	}
	if meta, ok := btf[ent.Name]; ok {
		return withFlags(meta, ent.Flags)
	}
	if meta, ok := l.aliasedBTFMeta(ent.Name, btf); ok {
		meta.Name = ent.Name
		return withFlags(meta, ent.Flags)
	}
	return dummySyscallMeta(ent)
}

func (l syscallMetadataLoader) aliasedBTFMeta(name string, btf map[string]SyscallMeta) (SyscallMeta, bool) {
	for btfName, syscallentName := range l.aliases {
		if syscallentName != name {
			continue
		}
		meta, ok := btf[btfName]
		return meta, ok
	}
	return SyscallMeta{}, false
}

func withFlags(meta SyscallMeta, flags string) SyscallMeta {
	meta.Flags = flags
	return meta
}

func dummySyscallMeta(ent syscallentEntry) SyscallMeta {
	args := make([]string, ent.Argc)
	argTypes := make([]string, ent.Argc)
	for i := 0; i < ent.Argc; i++ {
		args[i] = fmt.Sprintf("arg%d", i)
		argTypes[i] = "unsigned long"
	}
	return SyscallMeta{Name: ent.Name, Args: args, ArgTypes: argTypes, Flags: ent.Flags}
}
