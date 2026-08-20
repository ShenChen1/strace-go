package main

import (
	"regexp"

	"strace-go/pkg/cli"
)

// traceBPFConfig is the immutable bootstrap snapshot consumed by BPF setup.
// It deliberately contains no output, handler, or session-runtime policy.
type traceBPFConfig struct {
	captureStack  bool
	followForks   bool
	emitEnter     bool
	fdState       bool
	syscallFilter syscallFilterPlan
}

func newTraceBPFConfig(opts *cli.Options) traceBPFConfig {
	if opts == nil {
		return traceBPFConfig{}
	}
	filterInput := syscallFilterInput{
		names:   copyStringBoolMap(opts.TraceSyscalls),
		regexps: append([]*regexp.Regexp(nil), opts.TraceSyscallRegexps...),
		negated: opts.TraceSetIsNegated,
	}
	return traceBPFConfig{
		captureStack:  opts.StackTrace,
		followForks:   opts.FollowForks,
		emitEnter:     shouldEmitGenericEnter(opts),
		fdState:       len(opts.TracePaths) > 0 || opts.ShowPaths,
		syscallFilter: buildSyscallFilterPlan(filterInput),
	}
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
	// Lifecycle events always flow so task/fd state and attach exit status work
	// in text mode too; JSON rendering is gated separately.
	cfgVal |= bpfConfigEmitLifecycle
	if config.fdState {
		// -P filtering and -y/-yy fd path rendering both need a deterministic
		// fd -> path map, including when the syscall filter excludes fd updates.
		cfgVal |= bpfConfigFdState
	}
	syscallFilterCfg, err := configureSyscallFilter(config.syscallFilter, maps)
	if err != nil {
		return 0, err
	}
	return cfgVal | syscallFilterCfg, nil
}
