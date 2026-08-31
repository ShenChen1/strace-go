package main

import (
	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
	"strace-go/pkg/stacktrace"
)

// traceSessionConfig is the construction-time snapshot passed to session
// composition. It does not contain the mutable CLI owner.
type traceSessionConfig struct {
	eventPolicy    *cliTraceEventPolicy
	outputPolicy   *cliTraceOutputPolicy
	detachOnExecve bool
	syscallLimit   uint64
	summaryOptions summaryOptions
	catalog        *meta.Catalog
	decoder        *event.Decoder
	resolver       *stacktrace.Resolver
}

func newTraceSessionConfig(opts *cli.Options) traceSessionConfig {
	if opts == nil {
		return traceSessionConfig{}
	}
	decoder := event.NewDecoder()
	decoder.HexEscapeMode = opts.HexEscapeMode
	decoder.StringLimit = opts.StringLimit
	var resolver *stacktrace.Resolver
	if opts.StackTrace || opts.InstructionPointer {
		resolver = stacktrace.NewResolver()
	}
	return traceSessionConfig{
		eventPolicy:    newTraceEventPolicy(opts),
		outputPolicy:   newTraceOutputPolicy(opts),
		detachOnExecve: opts.DetachOnExecve,
		syscallLimit:   opts.SyscallLimit,
		summaryOptions: newSummaryOptions(opts.SummarySortBy, opts.SummaryColumns),
		catalog:        meta.NewCatalog(opts.XlatFormat),
		decoder:        decoder,
		resolver:       resolver,
	}
}
