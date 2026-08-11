package main

import (
	"fmt"
	"sort"
	"strings"
)

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

type syscallNumberSource interface {
	LoadSyscallNumbers() ([]syscallNumberEntry, error)
}

type syscallMetadataResolutionLoader interface {
	LoadWithResolution() (map[int]syscallMetadataResolution, error)
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

func (defaultSyscallMetadataLoader) LoadWithResolution() (map[int]syscallMetadataResolution, error) {
	loader, err := newDefaultSyscallMetadataLoader()
	if err != nil {
		return nil, err
	}
	return loader.LoadWithResolution()
}

type syscallentFileSource string

func (s syscallentFileSource) LoadSyscallEntries() ([]syscallentEntry, error) {
	return parseSyscallent(string(s))
}

type syscallMetadataLoader struct {
	btfSource         btfSyscallSource
	tracepointSource  tracepointSyscallSource
	numberSource      syscallNumberSource
	semanticSource    syscallEntrySource
	semanticOverrides map[string]SyscallMeta
	aliases           map[string]string
}

type syscallMetadataSource string

const (
	metadataSourceSemanticOverride syscallMetadataSource = "semantic_override"
	metadataSourceBTF              syscallMetadataSource = "btf"
	metadataSourceBTFAlias         syscallMetadataSource = "btf_alias"
	metadataSourceTracepoint       syscallMetadataSource = "tracepoint"
	metadataSourceDummy            syscallMetadataSource = "dummy"
)

type syscallMetadataResolutionReason string

const (
	metadataReasonSemanticOverride        syscallMetadataResolutionReason = "semantic_override"
	metadataReasonBTFExactArity           syscallMetadataResolutionReason = "btf_exact_arity"
	metadataReasonBTFAliasExactArity      syscallMetadataResolutionReason = "btf_alias_exact_arity"
	metadataReasonTracepointExactArity    syscallMetadataResolutionReason = "tracepoint_exact_arity"
	metadataReasonNoKernelMetadata        syscallMetadataResolutionReason = "no_kernel_metadata"
	metadataReasonBTFArityMismatch        syscallMetadataResolutionReason = "btf_arity_mismatch"
	metadataReasonTracepointArityMismatch syscallMetadataResolutionReason = "tracepoint_arity_mismatch"
)

type syscallMetadataResolution struct {
	Meta   SyscallMeta
	Source syscallMetadataSource
	Reason syscallMetadataResolutionReason
}

type syscallMetadataResolver struct {
	btf               map[string]SyscallMeta
	tracepoint        map[string]SyscallMeta
	semanticOverrides map[string]SyscallMeta
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
		numberSource:      unixSyscallSource{},
		semanticSource:    syscallentFileSource(syscallentPath),
		semanticOverrides: semanticOverrides,
		aliases:           btfNameToSyscallent,
	}
	return loader, nil
}

func (l syscallMetadataLoader) Load() (map[int]SyscallMeta, error) {
	resolutions, err := l.LoadWithResolution()
	if err != nil {
		return nil, err
	}
	result := make(map[int]SyscallMeta, len(resolutions))
	for id, resolution := range resolutions {
		result[id] = resolution.Meta
	}
	return result, nil
}

func (l syscallMetadataLoader) LoadWithResolution() (map[int]syscallMetadataResolution, error) {
	btf, err := l.btfSource.LoadBTFSyscalls()
	if err != nil {
		return nil, err
	}
	if l.numberSource == nil {
		return nil, fmt.Errorf("syscall number source is not configured")
	}
	numbers, err := l.numberSource.LoadSyscallNumbers()
	if err != nil {
		return nil, fmt.Errorf("load syscall numbers: %w", err)
	}
	if l.semanticSource == nil {
		return nil, fmt.Errorf("syscall semantic source is not configured")
	}
	semanticEntries, err := l.semanticSource.LoadSyscallEntries()
	if err != nil {
		return nil, fmt.Errorf("load syscall semantic entries: %w", err)
	}
	entries, err := mergeSyscallEntries(numbers, semanticEntries)
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
		aliases:           l.aliases,
	}
	res := make(map[int]syscallMetadataResolution, len(entries))
	for _, ent := range entries {
		res[ent.ID] = resolver.Resolve(ent)
	}
	return res, nil
}

func mergeSyscallEntries(numbers []syscallNumberEntry, semanticEntries []syscallentEntry) ([]syscallentEntry, error) {
	semanticByName := make(map[string]syscallentEntry, len(semanticEntries))
	for _, entry := range semanticEntries {
		if _, exists := semanticByName[entry.Name]; exists {
			return nil, fmt.Errorf("duplicate semantic metadata for syscall %s", entry.Name)
		}
		semanticByName[entry.Name] = entry
	}

	entries := make([]syscallentEntry, 0, len(numbers))
	seenIDs := make(map[int]string, len(numbers))
	for _, number := range numbers {
		if previousName, exists := seenIDs[number.ID]; exists {
			return nil, fmt.Errorf("duplicate syscall number %d for %s and %s", number.ID, previousName, number.Name)
		}
		semantic, ok := semanticByName[number.Name]
		if !ok {
			return nil, fmt.Errorf("missing semantic metadata for syscall %s", number.Name)
		}
		seenIDs[number.ID] = number.Name
		semantic.ID = number.ID
		semantic.Name = number.Name
		entries = append(entries, semantic)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})
	return entries, nil
}

func (r syscallMetadataResolver) Resolve(ent syscallentEntry) syscallMetadataResolution {
	if meta, ok := r.semanticOverrides[ent.Name]; ok {
		return r.resolution(meta, ent.Flags, metadataSourceSemanticOverride, metadataReasonSemanticOverride)
	}
	if meta, ok := r.btfMeta(ent.Name, ent.Argc); ok {
		return r.resolution(meta, ent.Flags, metadataSourceBTF, metadataReasonBTFExactArity)
	}
	if meta, ok := r.aliasedBTFMeta(ent.Name, ent.Argc); ok {
		meta.Name = ent.Name
		return r.resolution(meta, ent.Flags, metadataSourceBTFAlias, metadataReasonBTFAliasExactArity)
	}
	if meta, ok := r.tracepointMeta(ent.Name, ent.Argc); ok {
		meta.Name = ent.Name
		return r.resolution(meta, ent.Flags, metadataSourceTracepoint, metadataReasonTracepointExactArity)
	}
	return syscallMetadataResolution{
		Meta:   dummySyscallMeta(ent),
		Source: metadataSourceDummy,
		Reason: r.kernelMetadataRejectionReason(ent),
	}
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

func (syscallMetadataResolver) resolution(meta SyscallMeta, flags string, source syscallMetadataSource, reason syscallMetadataResolutionReason) syscallMetadataResolution {
	return syscallMetadataResolution{Meta: withFlags(meta, flags), Source: source, Reason: reason}
}

func (r syscallMetadataResolver) kernelMetadataRejectionReason(ent syscallentEntry) syscallMetadataResolutionReason {
	reasons := make([]string, 0, 2)
	if r.btfArityMismatch(ent) {
		reasons = append(reasons, string(metadataReasonBTFArityMismatch))
	}
	if r.tracepointArityMismatch(ent) {
		reasons = append(reasons, string(metadataReasonTracepointArityMismatch))
	}
	if len(reasons) == 0 {
		return metadataReasonNoKernelMetadata
	}
	return syscallMetadataResolutionReason(strings.Join(reasons, ";"))
}

func (r syscallMetadataResolver) btfArityMismatch(ent syscallentEntry) bool {
	if meta, ok := r.btf[ent.Name]; ok && !hasSyscallArity(meta, ent.Argc) {
		return true
	}
	for btfName, syscallentName := range r.aliases {
		if syscallentName != ent.Name {
			continue
		}
		if meta, ok := r.btf[btfName]; ok && !hasSyscallArity(meta, ent.Argc) {
			return true
		}
	}
	return false
}

func (r syscallMetadataResolver) tracepointArityMismatch(ent syscallentEntry) bool {
	for _, name := range append([]string{ent.Name}, tracepointAliasNames(ent.Name, r.aliases)...) {
		if meta, ok := r.tracepoint[name]; ok && !hasSyscallArity(meta, ent.Argc) {
			return true
		}
	}
	return false
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
