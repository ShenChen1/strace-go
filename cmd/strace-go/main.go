package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"strace-go/pkg/cli"
)

const (
	bpfConfigCaptureStack         = 1 << 0
	bpfConfigFollowForks          = 1 << 1
	bpfConfigEmitEnter            = 1 << 2
	bpfConfigSyscallFilter        = 1 << 3
	bpfConfigSyscallFilterNegated = 1 << 4
	bpfConfigEmitLifecycle        = 1 << 5
	bpfConfigFdState              = 1 << 6
)

//go:generate go run -C ../generate-syscalls .
//go:generate go run ../generate-xlats
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/strace.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

// IMPACT: main is the final process error boundary; resource-owning bootstrap
// work stays in error-returning helpers so deferred cleanup always runs.
func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "strace-go: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string) error {
	opts := cli.ParseArgs(args)
	handlePrelude(opts)
	normalizeTraceTargetOptions(opts)
	opts.TracePaths = expandTracePathSet(opts.TracePaths)
	return runTraceSession(newTraceLaunchConfig(opts), systemTraceClock{})
}

func runTraceSession(config *traceLaunchConfig, clock traceClock) (runErr error) {
	if config == nil {
		return fmt.Errorf("trace launch config is nil")
	}
	if clock == nil {
		return fmt.Errorf("trace clock is nil")
	}
	bpfRuntime, err := setupBPF()
	if err != nil {
		return fmt.Errorf("failed to set up BPF runtime: %w", err)
	}
	defer func() { runErr = joinTraceRunError(runErr, bpfRuntime.Close()) }()

	events, err := bpfRuntime.newEventReader()
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	defer func() { runErr = joinTraceRunError(runErr, events.Close()) }()

	if err := bpfRuntime.configure(config.bpfConfig); err != nil {
		return fmt.Errorf("failed to configure BPF runtime: %w", err)
	}

	targetBootstrap, err := newTraceTargetBootstrap(bpfRuntime)
	if err != nil {
		return fmt.Errorf("failed to set up target bootstrap: %w", err)
	}
	defer func() { runErr = joinTraceRunError(runErr, targetBootstrap.Close()) }()

	targetRuntime, targetPid, fdSeed, err := targetBootstrap.Resolve(config.targets)
	if err != nil {
		return fmt.Errorf("failed to resolve trace targets: %w", err)
	}
	targetHandoff, err := newTraceTargetHandoff(config.targets, targetRuntime, bpfRuntime, targetPid)
	if err != nil {
		return fmt.Errorf("failed to own trace targets: %w", errors.Join(err, targetBootstrap.abortTraceTarget(targetRuntime, targetPid)))
	}
	defer func() { runErr = joinTraceRunError(runErr, targetHandoff.Close()) }()

	output, err := setupOutput(config.outputPath, config.outputAppend)
	if err != nil {
		return fmt.Errorf("failed to set up output: %w", err)
	}
	outputHandoff, err := newTraceOutputHandoff(output)
	if err != nil {
		return fmt.Errorf("failed to own output: %w", joinTraceRunError(err, output.Close()))
	}
	defer func() { runErr = joinTraceRunError(runErr, outputHandoff.Close()) }()

	session, err := composeTraceSession(config.session, clock, traceSessionBootstrap{
		hasCommand:    targetRuntime != nil,
		commandWaiter: targetRuntime.commandWaiter(),
		events:        events,
		targetPID:     targetPid,
		fdSeed:        fdSeed,
		bpfReads:      bpfRuntime.readPorts(),
	}, outputHandoff.Output())
	if err != nil {
		return fmt.Errorf("failed to compose trace session: %w", err)
	}
	if err := outputHandoff.Transfer(); err != nil {
		return fmt.Errorf("failed to transfer output ownership: %w", err)
	}
	session.emitDebugReady()
	if err := session.run(); err != nil {
		return fmt.Errorf("failed to finalize trace session: %w", err)
	}
	if err := targetHandoff.Transfer(); err != nil {
		return fmt.Errorf("failed to transfer trace target ownership: %w", err)
	}
	return nil
}

func joinTraceRunError(primary error, cleanup error) error {
	return errors.Join(primary, cleanup)
}

// handlePrelude handles help/version requests and rejects sessions without targets.
func handlePrelude(opts *cli.Options) {
	if opts.HelpRequested {
		fmt.Printf("%s", cli.HelpText)
		os.Exit(0)
	}
	if opts.VersionRequested {
		fmt.Printf("strace -- version 6.19\n")
		fmt.Printf("Copyright (c) 1991-2026 The strace developers <https://strace.io>.\n")
		fmt.Printf("This is free software; see the source for copying conditions.  There is NO\n")
		fmt.Printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n")
		fmt.Printf("Optional features enabled: stack-trace=libunwind stack-demangle m32-mpers mx32-mpers\n")
		os.Exit(0)
	}
	if len(opts.CmdArgs) == 0 && len(opts.AttachPids) == 0 {
		fmt.Println("Usage: strace-go [options] <command> [args...]")
		os.Exit(1)
	}
}

// normalizeTraceTargetOptions resolves implicit lifecycle policy before BPF
// configuration and target startup. The parsed options are read-only after
// this bootstrap step.
func normalizeTraceTargetOptions(opts *cli.Options) {
	if opts == nil {
		return
	}
	if len(opts.AttachPids) > 1 || (len(opts.CmdArgs) > 0 && len(opts.AttachPids) > 0) {
		opts.FollowForks = true
	}
}

// expandTracePathSet mirrors upstream strace's pathtrace_select_set: each -P
// entry is kept as given and also stored as its absolute realpath, so
// event-sourced absolute fd targets can still match a relative -P argument
// such as "-P stat.sample".
func expandTracePathSet(paths map[string]bool) map[string]bool {
	if len(paths) == 0 {
		return paths
	}
	expanded := make(map[string]bool, len(paths)*2)
	for p := range paths {
		expanded[p] = true
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			expanded[resolved] = true
		} else {
			expanded[abs] = true
		}
	}
	return expanded
}

func calculateTimeOffsetWithClock(clock traceClock) int64 {
	if clock == nil {
		return 0
	}
	return clock.Now().UnixNano() - int64(clock.NowMonoNs())
}

func shouldEmitGenericEnter(opts *cli.Options) bool {
	if opts == nil {
		return false
	}
	if opts.EventFormat == cli.EventFormatJSON || len(opts.TracePaths) > 0 {
		return true
	}
	return !opts.SummaryOnly
}
