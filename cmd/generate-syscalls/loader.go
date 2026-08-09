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
	btfSource         btfSyscallSource
	tracepointSource  tracepointSyscallSource
	entrySource       syscallEntrySource
	semanticOverrides map[string]SyscallMeta
	fallbackOverrides map[string]SyscallMeta
	aliases           map[string]string
}

type syscallMetadataSource string

const (
	metadataSourceSemanticOverride syscallMetadataSource = "semantic_override"
	metadataSourceBTF              syscallMetadataSource = "btf"
	metadataSourceBTFAlias         syscallMetadataSource = "btf_alias"
	metadataSourceTracepoint       syscallMetadataSource = "tracepoint"
	metadataSourceFallbackOverride syscallMetadataSource = "fallback_override"
	metadataSourceDummy            syscallMetadataSource = "dummy"
)

type syscallMetadataResolution struct {
	Meta   SyscallMeta
	Source syscallMetadataSource
}

type syscallMetadataResolver struct {
	btf               map[string]SyscallMeta
	tracepoint        map[string]SyscallMeta
	semanticOverrides map[string]SyscallMeta
	fallbackOverrides map[string]SyscallMeta
	aliases           map[string]string
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
		btfSource:         kernelBTFSource{},
		tracepointSource:  kernelTracepointFormatSource{},
		entrySource:       syscallentFileSource(syscallentPath),
		semanticOverrides: semanticOverrides,
		fallbackOverrides: fallbackOverrides,
		aliases:           btfNameToSyscallent,
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
	tracepoint := map[string]SyscallMeta{}
	if l.tracepointSource != nil {
		names := make([]string, 0, len(entries))
		for _, ent := range entries {
			names = append(names, ent.Name)
		}
		names = tracepointLookupNames(names, l.aliases)
		tracepoint, err = l.tracepointSource.LoadTracepointSyscalls(names)
		if err != nil {
			return nil, err
		}
	}
	resolver := syscallMetadataResolver{
		btf:               btf,
		tracepoint:        tracepoint,
		semanticOverrides: l.semanticOverrides,
		fallbackOverrides: l.fallbackOverrides,
		aliases:           l.aliases,
	}
	res := make(map[int]SyscallMeta, len(entries))
	for _, ent := range entries {
		res[ent.ID] = resolver.Resolve(ent).Meta
	}
	return res, nil
}

func (r syscallMetadataResolver) Resolve(ent syscallentEntry) syscallMetadataResolution {
	if meta, ok := r.semanticOverrides[ent.Name]; ok {
		return r.resolution(meta, ent.Flags, metadataSourceSemanticOverride)
	}
	if meta, ok := r.btfMeta(ent.Name, ent.Argc); ok {
		return r.resolution(meta, ent.Flags, metadataSourceBTF)
	}
	if meta, ok := r.aliasedBTFMeta(ent.Name, ent.Argc); ok {
		meta.Name = ent.Name
		return r.resolution(meta, ent.Flags, metadataSourceBTFAlias)
	}
	if meta, ok := r.tracepointMeta(ent.Name, ent.Argc); ok {
		meta.Name = ent.Name
		return r.resolution(meta, ent.Flags, metadataSourceTracepoint)
	}
	if meta, ok := r.fallbackOverrides[ent.Name]; ok {
		return r.resolution(meta, ent.Flags, metadataSourceFallbackOverride)
	}
	return syscallMetadataResolution{Meta: dummySyscallMeta(ent), Source: metadataSourceDummy}
}

func (r syscallMetadataResolver) btfMeta(name string, argc int) (SyscallMeta, bool) {
	meta, ok := r.btf[name]
	if !ok || !hasSyscallArity(meta, argc) {
		return SyscallMeta{}, false
	}
	return meta, true
}

func (r syscallMetadataResolver) tracepointMeta(name string, argc int) (SyscallMeta, bool) {
	candidates := append([]string{name}, tracepointAliasNames(name, r.aliases)...)
	for _, candidate := range candidates {
		meta, ok := r.tracepoint[candidate]
		if ok && hasSyscallArity(meta, argc) {
			return meta, true
		}
	}
	return SyscallMeta{}, false
}

func (r syscallMetadataResolver) aliasedBTFMeta(name string, argc int) (SyscallMeta, bool) {
	for btfName, syscallentName := range r.aliases {
		if syscallentName != name {
			continue
		}
		meta, ok := r.btfMeta(btfName, argc)
		return meta, ok
	}
	return SyscallMeta{}, false
}

func (syscallMetadataResolver) resolution(meta SyscallMeta, flags string, source syscallMetadataSource) syscallMetadataResolution {
	return syscallMetadataResolution{Meta: withFlags(meta, flags), Source: source}
}

func hasSyscallArity(meta SyscallMeta, argc int) bool {
	return len(meta.Args) == argc && len(meta.ArgTypes) == argc
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
