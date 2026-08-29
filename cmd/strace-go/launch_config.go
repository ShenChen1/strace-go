package main

import "strace-go/pkg/cli"

type traceTargetConfig struct {
	command    traceCommandSpec
	attachPIDs []int
}

// traceLaunchConfig is the immutable bootstrap input for one trace run.
// It ends at session construction and is never stored in traceSessionDeps.
type traceLaunchConfig struct {
	bpfConfig    traceBPFConfig
	session      traceSessionConfig
	targets      traceTargetConfig
	outputPath   string
	outputAppend bool
	outputColor  string
	textOutput   bool
	tipsMode     string
	tipsID       int
}

func newTraceLaunchConfig(opts *cli.Options) *traceLaunchConfig {
	if opts == nil {
		return nil
	}
	return &traceLaunchConfig{
		bpfConfig: newTraceBPFConfig(opts),
		session:   newTraceSessionConfig(opts),
		targets: traceTargetConfig{
			command:    traceCommandSpecFromCLI(opts),
			attachPIDs: append([]int(nil), opts.AttachPids...),
		},
		outputPath:   opts.OutFile,
		outputAppend: opts.OutAppendMode,
		outputColor:  opts.ColorMode,
		textOutput:   opts.EventFormat == cli.EventFormatText,
		tipsMode:     opts.TipsMode,
		tipsID:       opts.TipsID,
	}
}

func traceCommandSpecFromCLI(opts *cli.Options) traceCommandSpec {
	if opts == nil {
		return traceCommandSpec{}
	}
	return traceCommandSpec{
		args:       append([]string(nil), opts.CmdArgs...),
		envActions: append([]string(nil), opts.EnvActions...),
		argv0:      opts.Argv0,
		argv0Set:   opts.Argv0Set,
	}
}
