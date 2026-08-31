package main

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/cilium/ebpf"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

// traceBPFConfig is the immutable bootstrap snapshot consumed by BPF setup.
// It deliberately contains no output, handler, or session-runtime policy.
type traceBPFConfig struct {
	captureStack               bool
	followForks                bool
	emitEnter                  bool
	emitSignal                 bool
	decodePIDsComm             bool
	namespaceNew               bool
	fdState                    bool
	elidePlainEnter            bool
	elideNonBlockingPlainEnter bool
	eventRingbufCapacity       uint32
	syscallFilter              syscallFilterPlan
}

func newTraceBPFConfig(opts *cli.Options) traceBPFConfig {
	if opts == nil {
		return traceBPFConfig{eventRingbufCapacity: traceDefaultEventRingbufCapacity}
	}
	traceConfigured := opts.TraceConfigured || opts.TraceSetIsNegated ||
		len(opts.TraceSyscalls) > 0 || len(opts.TraceSyscallRegexps) > 0
	filterInput := syscallFilterInput{
		names:      copyStringBoolMap(opts.TraceSyscalls),
		regexps:    append([]*regexp.Regexp(nil), opts.TraceSyscallRegexps...),
		configured: traceConfigured,
		matchesAll: opts.TraceMatchesAll,
		negated:    opts.TraceSetIsNegated,
	}
	syscallFilter := buildSyscallFilterPlan(filterInput)
	if opts.DetachOnExecve {
		syscallFilter = includeSyscalls(syscallFilter, "execve", "execveat")
	}
	fdState := len(opts.TracePaths) > 0 || opts.ShowPaths
	return traceBPFConfig{
		captureStack:               opts.StackTrace || opts.InstructionPointer,
		followForks:                opts.FollowForks,
		emitEnter:                  shouldEmitGenericEnter(opts),
		emitSignal:                 shouldEmitSignalEvents(opts),
		decodePIDsComm:             opts.DecodePIDsComm,
		namespaceNew:               opts.NamespaceNew,
		fdState:                    fdState,
		elidePlainEnter:            shouldElidePlainEnter(opts, fdState),
		elideNonBlockingPlainEnter: shouldElideNonBlockingPlainEnter(opts, fdState),
		eventRingbufCapacity:       traceDefaultEventRingbufCapacity,
		syscallFilter:              syscallFilter,
	}
}

func normalizeTraceBPFConfig(config traceBPFConfig) (traceBPFConfig, error) {
	if config.eventRingbufCapacity == 0 {
		config.eventRingbufCapacity = traceDefaultEventRingbufCapacity
	}
	if err := validateEventRingbufCapacity(config.eventRingbufCapacity); err != nil {
		return traceBPFConfig{}, err
	}
	return config, nil
}

// buildRuntimeConfig computes the BPF config map value from the bootstrap
// snapshot and the syscall filter, returning an error for map update failures.
func buildRuntimeConfig(config traceBPFConfig, maps bpfMapProvider) (uint32, error) {
	var cfgVal uint32
	if config.captureStack {
		cfgVal |= bpfConfigCaptureStack
	}
	if config.followForks {
		cfgVal |= bpfConfigFollowForks
	}
	if config.emitEnter {
		cfgVal |= bpfConfigEmitEnter
	}
	if config.emitSignal {
		cfgVal |= bpfConfigEmitSignal
	}
	if config.decodePIDsComm {
		cfgVal |= bpfConfigDecodePIDComm
	}
	// Lifecycle events always flow so task/fd state and attach exit status work
	// in text mode too; JSON rendering is gated separately.
	cfgVal |= bpfConfigEmitLifecycle
	if config.fdState {
		// -P filtering and -y/-yy fd path rendering both need a deterministic
		// fd -> path map, including when the syscall filter excludes fd updates.
		cfgVal |= bpfConfigFdState
	}
	if config.elidePlainEnter {
		if err := configurePlainEnterElision(maps, config.elideNonBlockingPlainEnter); err != nil {
			return 0, err
		}
		cfgVal |= bpfConfigElidePlainEnter
	}
	syscallFilterCfg, err := configureSyscallFilter(config.syscallFilter, maps)
	if err != nil {
		return 0, err
	}
	return cfgVal | syscallFilterCfg, nil
}

func possibleCPUCount() (uint32, error) {
	count, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, fmt.Errorf("read possible CPU count: %w", err)
	}
	if count <= 0 || uint64(count) > uint64(^uint32(0)) {
		return 0, fmt.Errorf("possible CPU count %d is outside runtime ABI", count)
	}
	return uint32(count), nil
}

func configureBPFRuntimeMetadata(maps bpfMapProvider) error {
	if maps == nil {
		return fmt.Errorf("BPF runtime metadata map is unavailable")
	}
	metadataMap := maps.coreMap(bpfMapRuntimeMeta)
	if metadataMap == nil {
		return fmt.Errorf("BPF runtime metadata map is unavailable")
	}
	count, err := possibleCPUCount()
	if err != nil {
		return err
	}
	if err := metadataMap.Update(uint32(0), count, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update BPF possible CPU count: %w", err)
	}
	return nil
}

func configurePlainEnterElision(maps bpfMapProvider, nonBlockingOnly bool) error {
	if maps == nil {
		return fmt.Errorf("BPF plain-enter elision map is unavailable")
	}
	elideMap := maps.coreMap(bpfMapPlainEnterElide)
	if elideMap == nil {
		return fmt.Errorf("BPF plain-enter elision map is unavailable")
	}
	var enabled uint32 = 1
	for _, id := range plainEnterElisionIDs(nonBlockingOnly) {
		if err := elideMap.Update(id, enabled, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("configure plain-enter elision for syscall %d: %w", id, err)
		}
	}
	return nil
}

func plainEnterElisionIDs(nonBlockingOnly bool) []uint32 {
	ids := make([]uint32, 0, len(meta.SyscallTable))
	for id := range meta.SyscallTable {
		if shouldElidePlainEnterForSyscall(id, nonBlockingOnly) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func shouldElidePlainEnterForSyscall(sysID uint32, nonBlockingOnly bool) bool {
	if nonBlockingOnly {
		if shouldTrackUnfinishedSyscall(sysID) {
			return false
		}
		return isPlainGenericEnterExitRoute(sysID) || isStandaloneExitElisionRoute(sysID)
	}
	return isPlainGenericEnterExitRoute(sysID)
}

func shouldElidePlainEnter(opts *cli.Options, fdState bool) bool {
	return opts != nil && (opts.EventFormat == cli.EventFormatText ||
		opts.EventFormat == cli.EventFormatJSON || opts.EventFormat == cli.EventFormatHandler) &&
		!opts.DebugEvents && !fdState
}

func shouldElideNonBlockingPlainEnter(opts *cli.Options, fdState bool) bool {
	return opts != nil && opts.EventFormat == cli.EventFormatText && shouldElidePlainEnter(opts, fdState)
}

func shouldEmitSignalEvents(opts *cli.Options) bool {
	if opts == nil || opts.EventFormat != cli.EventFormatText || opts.SummaryOnly {
		return false
	}
	return !opts.SignalConfigured || opts.SignalMatchesAll || opts.SignalSetIsNegated || len(opts.TraceSignals) > 0
}
