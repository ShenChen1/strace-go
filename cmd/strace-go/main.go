package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"strace-go/pkg/cli"
)

//go:generate ../../scripts/generate-bpf.sh
//go:generate go run ../generate-version

// IMPACT: main is the final process error boundary; resource-owning bootstrap
// work stays in error-returning helpers so deferred cleanup always runs.
func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", invocationName(), mainErrorText(err))
		os.Exit(1)
	}
}

func mainErrorText(err error) string {
	if err == nil {
		return ""
	}
	var execErr *traceCommandExecError
	if errors.As(err, &execErr) {
		return execErr.Error()
	}
	var outputErr *traceOutputPathError
	if errors.As(err, &outputErr) {
		return outputErr.Error()
	}
	return err.Error()
}

func invocationName() string {
	if len(os.Args) > 0 && os.Args[0] != "" {
		return os.Args[0]
	}
	return "strace"
}

func runMain(args []string) error {
	if err := validateTracingArchitecture(); err != nil {
		return err
	}
	opts := cli.ParseArgs(args)
	handled, err := handlePrelude(opts)
	if err != nil || handled {
		return err
	}
	normalizeTraceTargetOptions(opts)
	opts.TracePaths = expandTracePathSet(opts.TracePaths)
	config := newTraceLaunchConfig(opts)
	if err := runTraceSession(config, systemTraceClock{}); err != nil {
		return err
	}
	return renderTraceTip(os.Stderr, config.tipsMode, config.tipsID)
}

func runTraceSession(config *traceLaunchConfig, clock traceClock) (runErr error) {
	if config == nil {
		return fmt.Errorf("trace launch config is nil")
	}
	if clock == nil {
		return fmt.Errorf("trace clock is nil")
	}
	targets, err := prepareTraceTargetConfig(config.targets, os.Geteuid())
	if err != nil {
		return err
	}
	cleanupObserver := newTraceCleanupPhaseWriter(config.session.outputPolicy, os.Stderr)
	cleanup := newTraceCleanupPlan(traceCleanupPlanDeps{
		Clock:    clock,
		Observer: cleanupObserver,
	})
	defer func() { runErr = joinTraceRunError(runErr, cleanup.Close()) }()
	bootstrapStartNS := clock.NowMonoNs()
	bpfRuntime, err := setupBPFWithConfig(clock, config.bpfConfig)
	if err != nil {
		return fmt.Errorf("failed to set up BPF runtime: %w", err)
	}
	if err := cleanup.Add("bpf_runtime", func() error {
		return bpfRuntime.closeWithDiagnostics(clock, cleanupObserver)
	}); err != nil {
		return fmt.Errorf("register BPF runtime cleanup: %w", err)
	}

	events, err := bpfRuntime.newEventReader()
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	if err := cleanup.Add("ringbuf_reader", events.Close); err != nil {
		return fmt.Errorf("register ringbuf cleanup: %w", err)
	}

	if err := bpfRuntime.configure(config.bpfConfig); err != nil {
		return fmt.Errorf("failed to configure BPF runtime: %w", err)
	}

	targetBootstrap, err := newTraceTargetBootstrap(bpfRuntime)
	if err != nil {
		return fmt.Errorf("failed to set up target bootstrap: %w", err)
	}
	if err := cleanup.Add("target_bootstrap", targetBootstrap.Close); err != nil {
		return fmt.Errorf("register target bootstrap cleanup: %w", err)
	}

	targetRuntime, targetPid, fdSeed, err := targetBootstrap.Resolve(targets)
	if err != nil {
		return fmt.Errorf("failed to resolve trace targets: %w", err)
	}
	targetHandoff, err := newTraceTargetHandoff(targets, targetRuntime, bpfRuntime, targetPid)
	if err != nil {
		return fmt.Errorf("failed to own trace targets: %w", errors.Join(err, targetBootstrap.abortTraceTarget(targetRuntime, targetPid)))
	}
	if err := cleanup.Add("target_handoff", targetHandoff.Close); err != nil {
		return fmt.Errorf("register target cleanup: %w", err)
	}

	output, err := setupConfiguredOutput(config)
	if err != nil {
		return fmt.Errorf("failed to set up output: %w", err)
	}
	if err := output.SelectPID(targetPid); err != nil {
		return fmt.Errorf("failed to select initial output pid: %w", errors.Join(err, output.Close()))
	}
	enableTraceColor(output, config.outputColor, config.textOutput)
	if shouldBufferTraceOutput(config.session.outputPolicy) {
		if err := output.EnableBuffer(traceOutputBufferSize); err != nil {
			return fmt.Errorf("failed to buffer output: %w", errors.Join(err, output.Close()))
		}
	}
	outputHandoff, err := newTraceOutputHandoff(output)
	if err != nil {
		return fmt.Errorf("failed to own output: %w", joinTraceRunError(err, output.Close()))
	}
	if err := cleanup.Add("output", outputHandoff.Close); err != nil {
		return fmt.Errorf("register output cleanup: %w", err)
	}

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
	session.emitDebugBPFSetupPhases(bpfRuntime.setupStages())
	session.emitDebugReadyAt(bootstrapStartNS)
	if err := session.run(); err != nil {
		return fmt.Errorf("failed to finalize trace session: %w", err)
	}
	if err := targetHandoff.Transfer(); err != nil {
		return fmt.Errorf("failed to transfer trace target ownership: %w", err)
	}
	return nil
}

func shouldBufferTraceOutput(policy traceFormatPolicy) bool {
	return policy != nil && !policy.DiscardEvents()
}

func joinTraceRunError(primary error, cleanup error) error {
	return errors.Join(primary, cleanup)
}

// handlePrelude handles requests that do not start a trace session.
func handlePrelude(opts *cli.Options) (bool, error) {
	if opts.HelpRequested {
		fmt.Printf("%s", cli.HelpText)
		os.Exit(0)
		return true, nil
	}
	if opts.VersionLevel > 0 {
		return true, renderVersion(os.Stdout, opts.VersionLevel)
	}
	if len(opts.CmdArgs) == 0 && len(opts.AttachPids) == 0 {
		if opts.TipsMode != "" {
			return true, renderTraceTip(os.Stderr, opts.TipsMode, opts.TipsID)
		}
		return true, fmt.Errorf(
			"must have PROG [ARGS] or -p PID\nTry '%s -h' for more information.",
			invocationName(),
		)
	}
	return false, nil
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
